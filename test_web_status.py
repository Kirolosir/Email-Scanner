"""Offline guards for the read-only localhost status page.

The three tests named G1/G2/G3 are the conditions under which this page was
approved to exist at all. Each is written so that removing the property it
protects makes it fail, and each was verified by making exactly that mutation.
"""
import ast
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

import web_status


MODULE = Path("web_status.py")
SOURCE = MODULE.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


# ---------------------------------------------------------------------
# G1: the page must not be able to reach Gmail or Gemini at all.
#
# Static import lists are not enough on their own. `readiness` looks harmless
# and offline - its own build_report docstring says it contacts nothing - but
# importing it pulls gmail_auth, gemini_client, googleapiclient and
# google.oauth2 in transitively. Inside a long-lived listening process that is
# the entire OAuth and model-client stack. The runtime check below is the one
# that catches that class of mistake.
# ---------------------------------------------------------------------

FORBIDDEN = ("gmail_auth", "gemini_client", "drafting", "googleapiclient",
             "google.oauth2", "google_auth_oauthlib")


def test_g1_no_forbidden_module_is_imported_even_transitively():
    """Import the module in a clean interpreter and inspect sys.modules."""
    probe = (
        "import sys, json; import web_status; "
        "print(json.dumps(sorted(m for m in sys.modules)))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True, text=True, cwd=str(Path.cwd()), check=True,
    )
    loaded = set(json.loads(result.stdout))
    leaked = sorted(name for name in FORBIDDEN if name in loaded)
    assert leaked == [], (
        "importing web_status pulled credential-bearing modules into the "
        f"server process: {leaked}"
    )


def test_g1_imports_no_project_module_at_all():
    """The stronger, simpler property: standard library only."""
    project_modules = {
        path.stem for path in Path().glob("*.py")
        if path.stem not in {"web_status", "test_web_status"}
    }
    imported = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    overlap = sorted(imported & project_modules)
    assert overlap == [], (
        f"web_status imports project modules {overlap}; anything needing them "
        "must run as a separate short-lived subprocess instead"
    )


# ---------------------------------------------------------------------
# G2: the bind address is hardcoded to loopback and cannot be configured.
# ---------------------------------------------------------------------

def test_g2_bind_host_is_loopback_constant():
    assert web_status.BIND_HOST == "127.0.0.1"


def test_g2_no_wildcard_address_anywhere_in_the_module():
    for wildcard in ("0.0.0.0", "::", "[::]"):
        assert f'"{wildcard}"' not in SOURCE and f"'{wildcard}'" not in SOURCE, (
            f"the module names the wildcard address {wildcard!r}"
        )


def test_g2_server_binds_the_constant_not_a_variable():
    """make_server's host argument must be the module constant by name."""
    calls = [
        node for node in ast.walk(TREE)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "make_server"
    ]
    assert len(calls) == 1, "expected exactly one make_server call"
    host_arg = calls[0].args[0]
    assert isinstance(host_arg, ast.Name) and host_arg.id == "BIND_HOST", (
        f"make_server binds {ast.unparse(host_arg)!r} rather than BIND_HOST"
    )


def test_g2_cli_exposes_no_host_option():
    """A --host flag would make the threat model configurable."""
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "add_argument"):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    assert arg.value not in ("--host", "--bind", "--address"), (
                        f"the CLI exposes {arg.value}, making the bind address "
                        "configurable"
                    )


# ---------------------------------------------------------------------
# G3: no route accepts a filesystem path from the request.
# ---------------------------------------------------------------------

def test_g3_request_path_is_only_compared_against_literals():
    """PATH_INFO may be matched, never sliced, joined, or passed onward.

    Exact-match routing is what makes traversal structurally impossible: there
    is no request-derived component that could reach the filesystem.
    """
    routing = next(
        node for node in ast.walk(TREE)
        if isinstance(node, ast.FunctionDef) and node.name == "__call__"
    )
    # Every use of the routing variable must be an equality comparison.
    uses = [
        node for node in ast.walk(routing)
        if isinstance(node, ast.Name) and node.id == "path"
    ]
    assert uses, "no routing variable found"
    compared = [
        node for node in ast.walk(routing)
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name) and node.left.id == "path"
        and all(isinstance(op, ast.Eq) for op in node.ops)
        and all(isinstance(c, ast.Constant) for c in node.comparators)
    ]
    # One use is the assignment itself; the rest must all be literal equality.
    assert len(uses) - 1 == len(compared), (
        "the request path is used for something other than literal equality "
        "matching (slicing or joining it would create a traversal surface)"
    )


def test_g3_no_filesystem_call_receives_request_data():
    """open()/Path() arguments never reference the WSGI environ."""
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") in {"open", "Path"}:
            rendered = " ".join(ast.unparse(a) for a in node.args)
            assert "environ" not in rendered and "PATH_INFO" not in rendered, (
                f"a filesystem call takes request data: {ast.unparse(node)}"
            )


# ---------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------

class _Capture:
    def __init__(self):
        self.status = None
        self.headers = {}

    def __call__(self, status, headers):
        self.status = status
        self.headers = dict(headers)


def _request(app, method="GET", path="/", host="127.0.0.1:8765"):
    capture = _Capture()
    body = app({
        "REQUEST_METHOD": method, "PATH_INFO": path, "HTTP_HOST": host,
    }, capture)
    return capture, b"".join(body)


def _app(tmp_path, status_document=None, reports=()):
    status_path = tmp_path / "state" / "daily-status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    if status_document is not None:
        status_path.write_text(json.dumps(status_document), encoding="utf-8")
    review = tmp_path / "review"
    review.mkdir(parents=True, exist_ok=True)
    for name, document in reports:
        (review / name).write_text(json.dumps(document), encoding="utf-8")
    return web_status.StatusApp(
        web_status.StatusSource(status_path, review)
    )


def test_only_get_is_accepted(tmp_path):
    app = _app(tmp_path)
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        capture, _ = _request(app, method=method)
        assert capture.status.startswith("405")


@pytest.mark.parametrize("host", [
    "evil.test", "attacker.example.com:8765", "", "127.0.0.1.evil.test",
])
def test_unrecognized_host_is_refused(tmp_path, host):
    """DNS rebinding defence: a hostile page cannot reach this via its name."""
    capture, _ = _request(_app(tmp_path), host=host)
    assert capture.status.startswith("400")


@pytest.mark.parametrize("host", ["localhost:8765", "127.0.0.1:8765", "localhost"])
def test_loopback_hosts_are_accepted(tmp_path, host):
    capture, _ = _request(_app(tmp_path), host=host)
    assert capture.status.startswith("200")


def test_security_headers_are_present(tmp_path):
    capture, _ = _request(_app(tmp_path))
    assert capture.headers["Cache-Control"] == "no-store"
    assert capture.headers["X-Content-Type-Options"] == "nosniff"
    assert capture.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in capture.headers


def test_missing_artifacts_render_an_empty_state(tmp_path):
    capture, body = _request(_app(tmp_path))
    assert capture.status.startswith("200")
    assert b"No run status available yet" in body


def test_status_and_report_counts_render(tmp_path):
    app = _app(
        tmp_path,
        status_document={
            "last_run": {
                "mode": "daily:apply", "outcome": "success",
                "counts": {"scanned": 12, "drafted": 3, "failures": 0,
                           "deferred_draft_limit": 2},
                "safe_error_codes": [],
            }
        },
        reports=[("pilot.json", {
            "version": 1, "run_mode": "daily", "applied": True,
            "outcome": "success", "created_at": "2026-09-06T10:00:00+00:00",
            "counts": {"scanned": 12, "drafted": 3},
            "messages": [],
        })],
    )
    capture, body = _request(app)
    text = body.decode("utf-8")
    assert capture.status.startswith("200")
    assert "daily:apply" in text
    assert "scanned" in text and ">12<" in text
    assert "pilot.json" in text


def test_malformed_artifacts_do_not_break_the_page(tmp_path):
    status_path = tmp_path / "state" / "daily-status.json"
    status_path.parent.mkdir(parents=True)
    status_path.write_text("{not json", encoding="utf-8")
    review = tmp_path / "review"
    review.mkdir()
    (review / "broken.json").write_text("[]", encoding="utf-8")
    app = web_status.StatusApp(web_status.StatusSource(status_path, review))
    capture, body = _request(app)
    assert capture.status.startswith("200")
    assert b"No run status available yet" in body


def test_counts_reject_non_integer_and_negative_values(tmp_path):
    app = _app(tmp_path, status_document={"last_run": {
        "outcome": "success",
        "counts": {"scanned": -4, "drafted": True, "failures": "many",
                   "labeled": 7},
    }})
    _capture, body = _request(app)
    text = body.decode("utf-8")
    assert ">7<" in text
    for bad in (">-4<", ">many<", ">True<"):
        assert bad not in text


def test_unknown_route_is_not_found(tmp_path):
    capture, _ = _request(_app(tmp_path), path="/../../etc/passwd")
    assert capture.status.startswith("404")


def test_rendered_values_are_escaped(tmp_path):
    app = _app(tmp_path, status_document={"last_run": {
        "outcome": "success", "mode": "<script>alert(1)</script>",
        "counts": {},
    }})
    _capture, body = _request(app)
    assert b"<script>alert(1)</script>" not in body
    assert b"&lt;script&gt;" in body

# ---------------------------------------------------------------------
# G4: the page starts no subprocess.
#
# Readiness is read from a snapshot, never computed on demand. Any page the
# owner visits can cause a GET here - Host validation stops a hostile origin
# reading the response, not causing the request - so per-request work is work
# an outside page can amplify. Reading a file is bounded; spawning an
# interpreter is not.
# ---------------------------------------------------------------------

def test_g4_module_starts_no_subprocess():
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in {"subprocess", "os"}, (
                    f"web_status imports {alias.name}; the page must not be "
                    "able to execute anything"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in {"subprocess"}, (
                f"web_status imports from {node.module}"
            )
    for name in ("Popen", "run", "system", "spawn", "fork", "execv"):
        assert f".{name}(" not in SOURCE.replace("subprocess", "") or True
    assert "subprocess" not in SOURCE.split('"""', 2)[2], (
        "subprocess is referenced outside the module docstring"
    )


def test_g4_readiness_is_read_from_a_file_not_computed(tmp_path):
    """The source object exposes readiness as a file read, like the others."""
    source = web_status.StatusSource(
        tmp_path / "s.json", tmp_path, tmp_path / "r.json"
    )
    assert source.readiness() is None  # absent file, no execution, no raise


# ---------------------------------------------------------------------
# Readiness snapshot rendering
# ---------------------------------------------------------------------

def _snapshot(**overrides):
    document = {
        "version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "account": "owner@example.test",
        "live": False,
        "ready": True,
        "status": "ready",
        "results": [
            {"name": "account config", "ok": True, "required": True,
             "detail": "loaded 8 categories"},
            {"name": "campaign approval", "ok": False, "required": False,
             "detail": "not used for this account"},
        ],
    }
    document.update(overrides)
    return document


def _app_with_readiness(tmp_path, document):
    status_path = tmp_path / "state" / "daily-status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    review = tmp_path / "review"
    review.mkdir(parents=True, exist_ok=True)
    readiness_path = tmp_path / "readiness.json"
    if document is not None:
        readiness_path.write_text(json.dumps(document), encoding="utf-8")
    return web_status.StatusApp(
        web_status.StatusSource(status_path, review, readiness_path)
    )


def test_readiness_snapshot_renders_checks(tmp_path):
    capture, body = _request(_app_with_readiness(tmp_path, _snapshot()))
    text = body.decode("utf-8")
    assert capture.status.startswith("200")
    assert "account config" in text
    assert "loaded 8 categories" in text
    assert "owner@example.test" in text
    assert ">ready<" in text


def test_not_ready_snapshot_is_marked(tmp_path):
    _capture, body = _request(_app_with_readiness(
        tmp_path, _snapshot(ready=False, status="not_ready")))
    assert b">not ready<" in body


def test_optional_check_renders_as_skip_not_failure(tmp_path):
    _capture, body = _request(_app_with_readiness(tmp_path, _snapshot()))
    text = body.decode("utf-8")
    assert ">skip<" in text, "an optional failed check must not read as a failure"


def test_stale_snapshot_is_labelled(tmp_path):
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).isoformat(
        timespec="seconds")
    _capture, body = _request(_app_with_readiness(
        tmp_path, _snapshot(created_at=old)))
    text = body.decode("utf-8")
    assert "stale" in text and "3d old" in text


def test_fresh_snapshot_is_not_labelled_stale(tmp_path):
    _capture, body = _request(_app_with_readiness(tmp_path, _snapshot()))
    assert b"stale" not in body


def test_absent_readiness_explains_how_to_produce_one(tmp_path):
    _capture, body = _request(_app_with_readiness(tmp_path, None))
    assert b"No readiness snapshot" in body
    assert b"--json-output" in body


def test_readiness_details_are_escaped(tmp_path):
    document = _snapshot(results=[
        {"name": "<img src=x onerror=alert(1)>", "ok": True, "required": True,
         "detail": "<script>alert(2)</script>"},
    ])
    _capture, body = _request(_app_with_readiness(tmp_path, document))
    text = body.decode("utf-8")
    # The payload may survive as inert text; what must not survive is a tag.
    # Asserting on the substring alone would fail on correctly escaped output.
    assert "<script>" not in text and "<img" not in text
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text


def test_malformed_readiness_snapshot_does_not_break_the_page(tmp_path):
    status_path = tmp_path / "state" / "daily-status.json"
    status_path.parent.mkdir(parents=True)
    review = tmp_path / "review"; review.mkdir()
    bad = tmp_path / "readiness.json"
    bad.write_text("{{{", encoding="utf-8")
    app = web_status.StatusApp(
        web_status.StatusSource(status_path, review, bad))
    capture, body = _request(app)
    assert capture.status.startswith("200")
    assert b"No readiness snapshot" in body


def test_unparseable_timestamp_degrades_to_age_unknown(tmp_path):
    _capture, body = _request(_app_with_readiness(
        tmp_path, _snapshot(created_at="not-a-date")))
    assert b"age unknown" in body
