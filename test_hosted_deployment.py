"""Guards on the deployment configuration itself.

A Dockerfile is code that runs with the deployment's privileges, and a
.dockerignore is a security control: it decides what gets republished to a
registry on every build. Neither is covered by the Python guards, so they get
their own.

The properties:

  D1  every secret .gitignore protects is also excluded from the image
  D2  the image copies only what the status service imports
  D3  the container does not run as root
  D4  the deployment's own modules stay importable with no environment
"""
import ast
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
DOCKERIGNORE = (ROOT / ".dockerignore").read_text(encoding="utf-8")
GITIGNORE = (ROOT / ".gitignore").read_text(encoding="utf-8")


def _patterns(text):
    """Ignore-file lines that actually exclude something.

    A trailing slash is stripped: `accounts/` and `accounts` exclude the same
    directory in both formats, and comparing spelling rather than meaning
    would make this guard fail over punctuation while missing a real gap.
    """
    return {
        line.strip().rstrip("/") for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
        and not line.strip().startswith("!")
    }


# ---------------------------------------------------------------------
# D1  secrets cannot enter the image
# ---------------------------------------------------------------------

# Directories excluded wholesale by .dockerignore cover their contents, so a
# .gitignore entry inside one of them needs no separate line.
COVERED_BY_PARENT = ("launchd/",)


def test_every_gitignored_secret_is_also_excluded_from_the_image():
    """D1: the two files must not drift.

    A secret kept out of the repository but copied into a pushed image is
    arguably worse off than one merely committed: images are pulled by layer
    cache and by anything with registry read access.
    """
    ignored = _patterns(GITIGNORE)
    excluded = _patterns(DOCKERIGNORE)

    missing = sorted(
        pattern for pattern in ignored - excluded
        if not any(pattern.startswith(prefix) for prefix in COVERED_BY_PARENT)
    )
    assert missing == [], (
        "these are kept out of git but would be copied into the image: "
        f"{missing}"
    )


@pytest.mark.parametrize("secret", [
    ".env", "*.key", "credentials.json", "token*.json", "client_secret*.json",
    "broker-operator*", "accounts", "review", "draft-logs",
])
def test_a_named_secret_is_excluded(secret):
    """The positive half: named explicitly so a rewrite cannot lose one."""
    assert secret in _patterns(DOCKERIGNORE)


def test_the_git_directory_is_excluded():
    """History contains every file ever committed, including deleted ones."""
    assert ".git" in _patterns(DOCKERIGNORE)


def test_example_files_are_not_excluded():
    """The negations must survive; they are what makes the examples shippable."""
    for kept in (".env.example", "broker.env.example", "hosted.env.example"):
        assert f"!{kept}" in DOCKERIGNORE


# ---------------------------------------------------------------------
# D2  the image carries only what it needs
# ---------------------------------------------------------------------

def _copied_modules():
    copied = set()
    for line in DOCKERFILE.splitlines():
        stripped = line.strip().rstrip("\\").strip()
        if stripped.startswith("COPY "):
            stripped = stripped[len("COPY "):]
        elif not copied and not stripped.endswith(".py"):
            continue
        copied.update(part for part in stripped.split() if part.endswith(".py"))
    return copied


def test_the_image_does_not_copy_the_whole_tree():
    """A broad COPY would pull in the Gmail and drafting modules."""
    for line in DOCKERFILE.splitlines():
        stripped = line.strip()
        if stripped.startswith("COPY "):
            assert stripped not in ("COPY . .", "COPY . /app", "COPY ./ ./"), (
                "the image copies the whole tree; it would carry modules this "
                "process has no business holding"
            )


def test_the_image_carries_exactly_the_status_service_import_closure():
    """D2: what is copied must match what hosted_status actually needs.

    Computed from the imports rather than retyped, so adding an import to
    hosted_status without adding it to the Dockerfile fails here instead of
    at the first request on a real deployment.
    """
    local = {path.name for path in ROOT.glob("*.py")}
    needed, seen = set(), set()
    pending = ["hosted_wsgi.py"]

    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        needed.add(name)
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module.split(".")[0]]
            for module in modules:
                if f"{module}.py" in local:
                    pending.append(f"{module}.py")

    copied = _copied_modules()
    assert needed - copied == set(), (
        f"the service imports these but the image does not copy them: "
        f"{sorted(needed - copied)}"
    )
    assert copied - needed == set(), (
        f"the image copies these but the service never imports them: "
        f"{sorted(copied - needed)}"
    )


def test_no_gmail_or_drafting_module_reaches_the_image():
    forbidden = {
        "gmail_auth.py", "gmail_common.py", "gmail_reader.py",
        "gmail_labeler.py", "drafting.py", "gemini_client.py", "triage.py",
        "daily_triage.py", "connection_tokens.py", "connection_kms.py",
        "connection_archive.py", "campaign.py",
    }
    assert _copied_modules() & forbidden == set()


# ---------------------------------------------------------------------
# D3  the container is not root
# ---------------------------------------------------------------------

def test_the_container_drops_to_an_unprivileged_user():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.MULTILINE)
    assert users, "the Dockerfile never leaves root"
    assert users[-1] not in ("root", "0")


def test_the_user_is_a_fixed_uid_so_a_volume_can_be_owned_to_match():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.MULTILINE)
    assert users[-1].isdigit(), (
        "USER must be a numeric uid; a name cannot be matched against a "
        "mounted volume's ownership"
    )


def test_the_user_switch_is_the_last_thing_before_the_command():
    """A RUN after USER would either fail or run unprivileged by surprise."""
    lines = [l.strip() for l in DOCKERFILE.splitlines()]
    user_at = max(i for i, l in enumerate(lines) if l.startswith("USER "))
    for later in lines[user_at + 1:]:
        assert not later.startswith(("RUN ", "COPY ", "ADD ")), (
            f"{later!r} runs after the USER switch"
        )


# ---------------------------------------------------------------------
# The environment example matches what the code reads
# ---------------------------------------------------------------------

def test_every_variable_the_service_reads_is_documented():
    source = (ROOT / "hosted_status.py").read_text(encoding="utf-8")
    example = (ROOT / "hosted.env.example").read_text(encoding="utf-8")
    for variable in re.findall(r'env\.get\("([A-Z_]+)"', source):
        assert variable in example, (
            f"{variable} is read but absent from hosted.env.example"
        )


def test_the_example_holds_no_filled_in_secret():
    """An example file with a real value in it is a committed secret."""
    for line in (ROOT / "hosted.env.example").read_text(
            encoding="utf-8").splitlines():
        if line.startswith("HOSTED_OPERATOR_BEARER"):
            assert line.strip() == "HOSTED_OPERATOR_BEARER="


def test_the_state_root_requirement_is_stated_where_it_will_be_read():
    """The GCS-FUSE trap must be documented, not only enforced."""
    for document in (DOCKERFILE, (ROOT / "hosted.env.example").read_text(
            encoding="utf-8")):
        assert "GCS-FUSE" in document or "GCS FUSE" in document
        assert "Filestore" in document


# ---------------------------------------------------------------------
# D4  nothing constructs at import
# ---------------------------------------------------------------------

def test_the_entry_point_needs_no_environment_to_import(monkeypatch):
    for variable in ("HOSTED_STATE_ROOT", "HOSTED_OPERATOR_BEARER"):
        monkeypatch.delenv(variable, raising=False)
    import importlib

    import hosted_wsgi
    importlib.reload(hosted_wsgi)
    assert hosted_wsgi._app is None
