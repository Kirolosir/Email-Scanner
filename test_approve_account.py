"""Offline tests for the one-step account approval builder."""
import json
import pytest
import os

import approve_account
from account_profile import load_profile


def _config(tmp_path):
    document = {
        "version": 1,
        "account": "owner@example.test",
        "timezone": "UTC",
        "taxonomy": [
            {
                "slug": "project",
                "display": "Project",
                "description": "A project request.",
                "examples": [],
                "label": "Triage/Project",
                "drafting": {"mode": "generic"},
            },
            {
                "slug": "receipt",
                "display": "Receipt",
                "description": "A receipt.",
                "examples": [],
                "label": "Triage/Receipt",
                "drafting": {"mode": "off"},
            },
        ],
        "system_labels": {
            "needs_review": "Triage/Needs Review",
            "processed": "Triage/Processed",
        },
    }
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return path


def test_documents_bind_exact_account_taxonomy_and_generic_subset(tmp_path):
    profile = load_profile(str(_config(tmp_path)))
    taxonomy, ai = approve_account.build_documents(
        profile, allow_protected_labels=True
    )

    assert taxonomy["account"] == "owner@example.test"
    assert set(taxonomy["confirmed_categories"]) == {"project", "receipt"}
    assert ai["approved_categories"] == ["project"]
    assert ai["allow_protected_labels"] is True


def test_write_is_private_exclusive_and_all_or_nothing(tmp_path):
    profile = load_profile(str(_config(tmp_path)))
    taxonomy, ai = approve_account.build_documents(profile)
    taxonomy_path = tmp_path / "private" / "taxonomy.json"
    ai_path = tmp_path / "private" / "ai.json"

    written = approve_account.write_documents(
        str(taxonomy_path), taxonomy, str(ai_path), ai
    )
    assert written == [str(taxonomy_path), str(ai_path)]
    assert os.stat(taxonomy_path).st_mode & 0o777 == 0o600
    assert os.stat(ai_path).st_mode & 0o777 == 0o600
    assert os.stat(taxonomy_path.parent).st_mode & 0o777 == 0o700

    before = taxonomy_path.read_bytes(), ai_path.read_bytes()
    try:
        approve_account.write_documents(
            str(taxonomy_path), taxonomy, str(ai_path), ai
        )
    except FileExistsError:
        pass
    assert (taxonomy_path.read_bytes(), ai_path.read_bytes()) == before


def test_dry_run_and_wrong_phrase_write_nothing(tmp_path, capsys):
    config = _config(tmp_path)
    taxonomy = tmp_path / "taxonomy.json"
    ai = tmp_path / "ai.json"
    base = [
        "--account-config", str(config),
        "--taxonomy-output", str(taxonomy),
        "--ai-output", str(ai),
    ]

    assert approve_account.main(base + ["--dry-run"]) == 0
    assert not taxonomy.exists() and not ai.exists()
    assert approve_account.main(base, reader=lambda _p: "yes") == 1
    assert not taxonomy.exists() and not ai.exists()
    assert "no network calls" in capsys.readouterr().out.casefold()


def test_exact_phrase_creates_both_approvals(tmp_path):
    config = _config(tmp_path)
    profile = load_profile(str(config))
    generic = ["project"]
    phrase = approve_account.confirmation_phrase(profile, generic)
    taxonomy = tmp_path / "taxonomy.json"
    ai = tmp_path / "ai.json"

    result = approve_account.main([
        "--account-config", str(config),
        "--taxonomy-output", str(taxonomy),
        "--ai-output", str(ai),
    ], reader=lambda _p: phrase)

    assert result == 0
    assert json.loads(ai.read_text())["approved_categories"] == ["project"]


# --------------------------------------------------------------------
# The protected-label grant must be confirmed, not merely flagged.
# --------------------------------------------------------------------

import contextlib
import io
import os
import tempfile

import approve_account
from account_profile import load_profile
from approve_account import build_documents, confirmation_phrase


def _pl_config(tmp_path, generic=("recruiting",)):
    document = {
        "version": 1, "account": "owner@example.test", "timezone": "UTC",
        "taxonomy": [
            {"slug": "recruiting", "description": "prospects",
             "examples": ["s"], "label": "Triage/Recruiting",
             "drafting": {"mode": "generic" if "recruiting" in generic else "off"}},
            {"slug": "marketing", "description": "promos", "examples": ["s"],
             "label": "Triage/Marketing", "drafting": {"mode": "off"}},
        ],
        "protected_labels": [{"label": "YEAR_LABEL"}],
    }
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return str(path)


def _pl_run(config_path, out_dir, typed, extra=()):
    argv = ["--account-config", config_path,
            "--taxonomy-output", os.path.join(out_dir, "tx.json"),
            "--ai-output", os.path.join(out_dir, "ai.json"), *extra]
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = approve_account.main(argv, reader=lambda _p: typed)
    return code, buffer.getvalue()


def test_protected_label_grant_changes_the_confirmed_sentence(tmp_path):
    """A strictly larger permission must not be obtainable by typing the
    same sentence. Before this, --allow-protected-labels granted generated drafting
    on protected-label messages while the owner confirmed wording that never
    mentioned it."""
    profile = load_profile(_pl_config(tmp_path))

    blocked = confirmation_phrase(profile, ["recruiting"],
                                  allow_protected_labels=False)
    allowed = confirmation_phrase(profile, ["recruiting"],
                                  allow_protected_labels=True)

    assert blocked != allowed
    assert "protected labels" in allowed
    assert "protected labels" not in blocked


def test_protected_flag_without_the_matching_phrase_is_refused(tmp_path):
    """End to end: passing the flag but typing the smaller sentence must
    write nothing."""
    config = _pl_config(tmp_path)
    profile = load_profile(config)
    smaller = confirmation_phrase(profile, ["recruiting"],
                                  allow_protected_labels=False)
    out = str(tmp_path / "out")

    code, text = _pl_run(config, out, smaller, extra=["--allow-protected-labels"])

    assert code == 1
    assert "did not match" in text
    assert not os.path.exists(os.path.join(out, "ai.json"))


def test_protected_flag_with_the_matching_phrase_is_granted(tmp_path):
    config = _pl_config(tmp_path)
    profile = load_profile(config)
    larger = confirmation_phrase(profile, ["recruiting"],
                                 allow_protected_labels=True)
    out = str(tmp_path / "out")

    code, _text = _pl_run(config, out, larger, extra=["--allow-protected-labels"])

    assert code == 0
    document = json.load(open(os.path.join(out, "ai.json")))
    assert document["allow_protected_labels"] is True


def test_main_passes_the_protected_flag_into_the_phrase(tmp_path):
    """Guards the wiring, not just the function: the fix is inert if main()
    keeps calling confirmation_phrase without the flag."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("approve_account.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "confirmation_phrase"
    ]
    assert calls, "approve_account no longer builds a confirmation phrase"
    for call in calls:
        supplied = {kw.arg for kw in call.keywords} | {
            f"pos{i}" for i in range(len(call.args))
        }
        assert "allow_protected_labels" in supplied or len(call.args) >= 3, (
            "confirmation_phrase is called without the protected-label grant"
        )


# --------------------------------------------------------------------
# One-time / replay
# --------------------------------------------------------------------

def test_a_replayed_confirmation_writes_nothing(tmp_path):
    config = _pl_config(tmp_path)
    profile = load_profile(config)
    phrase = confirmation_phrase(profile, ["recruiting"])
    out = str(tmp_path / "out")

    first, _ = _pl_run(config, out, phrase)
    assert first == 0

    second, text = _pl_run(config, out, phrase)
    assert second == 2
    assert "never overwrites" in text


def test_dry_run_writes_nothing_even_with_a_correct_phrase(tmp_path):
    config = _pl_config(tmp_path)
    profile = load_profile(config)
    phrase = confirmation_phrase(profile, ["recruiting"])
    out = str(tmp_path / "out")

    code, text = _pl_run(config, out, phrase, extra=["--dry-run"])

    assert code == 0
    assert "no approval files written" in text
    assert not os.path.exists(os.path.join(out, "tx.json"))


@pytest.mark.parametrize("typed", [
    "", "yes", "I reviewed 2 categories for owner@example.test",
    "i reviewed 2 categories for owner@example.test and approve generated "
    "drafts for 1 categories",
])
def test_near_miss_confirmations_are_refused(typed, tmp_path):
    """No case-insensitive or prefix matching."""
    config = _pl_config(tmp_path)
    out = str(tmp_path / "out")

    code, _text = _pl_run(config, out, typed)

    assert code == 1
    assert not os.path.exists(os.path.join(out, "tx.json"))


# --------------------------------------------------------------------
# Writing into a directory the user does not own
# --------------------------------------------------------------------

def test_writes_into_a_pre_existing_shared_directory(tmp_path):
    """chmod on a parent the tool did not create raises EPERM on a shared
    directory and aborted the write with a bare errno. The file is created
    0600 by its own open flags, so tightening the parent is best effort."""
    config = _pl_config(tmp_path)
    profile = load_profile(config)
    phrase = confirmation_phrase(profile, ["recruiting"])

    shared = tempfile.mkdtemp()          # exists already, not created by us
    os.chmod(shared, 0o755)

    code, text = _pl_run(config, shared, phrase)

    assert code == 0, text
    written = os.path.join(shared, "tx.json")
    assert oct(os.stat(written).st_mode)[-3:] == "600"


def test_approval_files_are_created_exclusively_and_owner_only():
    """A7. The trailing chmod leaves the file at 0600 even if the create
    flags are loosened, so the runtime mode cannot reveal a lost O_EXCL.
    O_EXCL is what makes the no-overwrite refusal race-free rather than a
    check that another process can win between.

    Asserted per function so one correct os.open cannot vouch for another.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(Path("approve_account.py").read_text(encoding="utf-8"))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_write_private_json"
    )
    opens = [
        ast.unparse(node) for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and "O_CREAT" in ast.unparse(node)
    ]
    assert opens, "_write_private_json does not create its file explicitly"
    for call in opens:
        assert "O_EXCL" in call, (
            "approval files must be created exclusively; the exists() check "
            "alone is a race another process can win"
        )
        # ast.unparse renders 0o600 as 384.
        assert "0o600" in call or "384" in call, (
            "approval files must be created owner-only, not chmod'd after"
        )
