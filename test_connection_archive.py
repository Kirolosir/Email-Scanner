"""Offline tests for disconnect, archiving and restoration.

The rules being pinned: the token is destroyed and never archived, consent is
archived but never restored, config and journal come back only for the same
address, and revocation is injected so nothing here reaches Google.
"""
import ast
import datetime as dt
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

import connection as conn
import connection_archive as arch
from connection_archive import (
    ARCHIVE,
    ARCHIVE_RESTORABLE,
    DESTROY,
    DISPOSITION,
    RESTORABLE,
    ArchiveError,
    archive_path,
    disconnect,
    read_manifest,
    restorable,
    restore,
)


A = "coach@example.test"
B = "someone.else@example.test"
T0 = dt.datetime(2026, 9, 6, 18, 0, tzinfo=dt.timezone.utc)

TOKEN_MARKER = "SECRET-REFRESH-VALUE"
CONSENT_MARKER = "I approve generated unsent drafts"


def _populated(tmp_path, account=A):
    """A connection with one of every artifact the system can produce."""
    connection = conn.connect(tmp_path, account, timezone="America/New_York",
                              run_at="18:00", now=T0)
    active = connection.directory
    active.mkdir(parents=True, exist_ok=True)
    (active / "token.enc.json").write_text(
        json.dumps({"ciphertext": TOKEN_MARKER}), encoding="utf-8")
    (active / "account.json").write_text(
        json.dumps({"account": account, "taxonomy": ["recruit"]}), encoding="utf-8")
    (active / "taxonomy-confirmation.json").write_text(
        json.dumps({"confirmed": {"recruit": "digest"}}), encoding="utf-8")
    (active / "ai-drafting-approval.json").write_text(
        json.dumps({"acknowledgement": CONSENT_MARKER}), encoding="utf-8")
    (active / "daily-state.json").write_text(
        json.dumps({"version": 1, "messages": {"m1": {"status": "complete"}}}),
        encoding="utf-8")
    (active / "daily-status.json").write_text(
        json.dumps({"version": 1, "last_run": {"outcome": "success"}}),
        encoding="utf-8")
    (active / "run-now-request.json").write_text(
        json.dumps({"version": 1}), encoding="utf-8")
    (active / "failures.log").write_text("===== a scrubbed trace\n", encoding="utf-8")
    for name in ("review", "draft-logs", "locks"):
        (active / name).mkdir(exist_ok=True)
    (active / "review" / "r.json").write_text("{}", encoding="utf-8")
    (active / "draft-logs" / "d.log").write_text("draft-1\n", encoding="utf-8")
    (active / "locks" / "run.lock").write_text("", encoding="utf-8")
    return connection


# ---------------------------------------------------------------------
# The disposition table is the policy
# ---------------------------------------------------------------------

def test_every_artifact_the_system_produces_has_an_explicit_disposition(tmp_path):
    """A new artifact must not quietly inherit a default nobody chose."""
    connection = _populated(tmp_path)
    produced = {entry.name for entry in connection.directory.iterdir()}
    undeclared = sorted(produced - set(DISPOSITION))
    assert undeclared == [], (
        f"artifacts with no declared disposition: {undeclared}"
    )


def test_only_credentials_and_coordination_artifacts_are_destroyed():
    destroyed = sorted(n for n, (k, _c) in DISPOSITION.items() if k == DESTROY)
    assert destroyed == ["locks", "run-now-request.json", "token.enc.json"]


def test_restorable_covers_config_and_journal_only():
    assert RESTORABLE == {"account.json", "daily-state.json"}


def test_no_consent_record_is_restorable():
    consent = [n for n, (_k, c) in DISPOSITION.items() if c == "consent"]
    assert consent, "the fixture no longer describes consent artifacts"
    for name in consent:
        assert DISPOSITION[name][0] == ARCHIVE
        assert name not in RESTORABLE


# ---------------------------------------------------------------------
# Disconnect
# ---------------------------------------------------------------------

def test_disconnect_vacates_the_deployment(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    assert conn.current(tmp_path) is None
    assert not connection.directory.exists()


def test_the_token_is_destroyed_and_exists_nowhere_afterwards(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)

    survivors = [p for p in Path(tmp_path).rglob("*") if p.is_file()]
    assert not any(p.name == "token.enc.json" for p in survivors)
    for path in survivors:
        assert TOKEN_MARKER not in path.read_text(encoding="utf-8", errors="replace"), (
            f"token material survived in {path.name}"
        )


def test_consent_is_archived_but_never_restorable(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    directory = archive_path(tmp_path, A)

    assert (directory / "ai-drafting-approval.json").exists()
    assert CONSENT_MARKER in (directory / "ai-drafting-approval.json").read_text()
    assert "ai-drafting-approval.json" not in restorable(tmp_path, A)
    assert "taxonomy-confirmation.json" not in restorable(tmp_path, A)


def test_config_and_journal_are_archived_and_restorable(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    assert restorable(tmp_path, A) == ["account.json", "daily-state.json"]


def test_history_is_archived(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    directory = archive_path(tmp_path, A)
    for name in ("daily-status.json", "failures.log", "review", "draft-logs"):
        assert (directory / name).exists(), f"{name} was not archived"


def test_locks_are_destroyed_not_archived(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    assert not (archive_path(tmp_path, A) / "locks").exists()


def test_an_unrecognised_artifact_is_archived_never_destroyed(tmp_path):
    """Conservative in both directions: keep it, but never hand it back."""
    connection = _populated(tmp_path)
    (connection.directory / "something-new.json").write_text("{}", encoding="utf-8")
    disconnect(connection, tmp_path, now=T0)
    directory = archive_path(tmp_path, A)
    assert (directory / "something-new.json").exists()
    assert "something-new.json" not in restorable(tmp_path, A)


def test_the_archive_is_named_by_hash_not_by_address(tmp_path):
    connection = _populated(tmp_path)
    disconnect(connection, tmp_path, now=T0)
    names = [p.name for p in (Path(tmp_path) / "archive").iterdir()]
    assert names and all("coach" not in n and "@" not in n for n in names)


def test_the_archive_lives_outside_the_active_directory(tmp_path):
    connection = _populated(tmp_path)
    active = connection.directory
    disconnect(connection, tmp_path, now=T0)
    assert not str(archive_path(tmp_path, A)).startswith(str(active))


def test_the_manifest_records_what_happened(tmp_path):
    connection = _populated(tmp_path)
    manifest = disconnect(connection, tmp_path, now=T0)
    assert manifest["version"] == arch.MANIFEST_VERSION
    assert "token.enc.json" in manifest["destroyed"]
    assert "locks" in manifest["destroyed"]
    assert "run-now-request.json" in manifest["destroyed"]
    assert "account.json" in manifest["archived"]
    assert manifest["restorable"] == ["account.json", "daily-state.json"]
    assert read_manifest(tmp_path, A) == manifest


# ---------------------------------------------------------------------
# Revocation is injected
# ---------------------------------------------------------------------

def test_no_revoker_is_recorded_not_silently_skipped(tmp_path):
    connection = _populated(tmp_path)
    manifest = disconnect(connection, tmp_path, now=T0)
    assert manifest["revocation"] == "not attempted"


def test_a_successful_revocation_is_recorded(tmp_path):
    connection = _populated(tmp_path)
    calls = []
    manifest = disconnect(connection, tmp_path, now=T0,
                          revoke=lambda doc: calls.append(doc) or True,
                          token_document={"refresh_token": TOKEN_MARKER})
    assert manifest["revocation"] == "revoked"
    assert calls == [{"refresh_token": TOKEN_MARKER}]


def test_a_failed_revocation_still_destroys_the_local_token(tmp_path):
    """A local copy nobody can revoke is worse than no local copy."""
    connection = _populated(tmp_path)

    def explode(_doc):
        raise OSError("network unreachable")

    manifest = disconnect(connection, tmp_path, now=T0, revoke=explode)
    assert "failed" in manifest["revocation"]
    assert not (archive_path(tmp_path, A) / "token.enc.json").exists()
    assert conn.current(tmp_path) is None


def test_a_refused_revocation_is_distinguishable_from_a_failure(tmp_path):
    connection = _populated(tmp_path)
    manifest = disconnect(connection, tmp_path, now=T0,
                          revoke=lambda _doc: False)
    assert manifest["revocation"] == "refused"


# ---------------------------------------------------------------------
# Restoration
# ---------------------------------------------------------------------

def test_a_returning_account_gets_config_and_journal_back(tmp_path):
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)

    again = conn.connect(tmp_path, A, timezone="America/New_York",
                         run_at="18:00", now=T0 + dt.timedelta(days=30))
    restored = restore(again, tmp_path, A)
    assert restored == ["account.json", "daily-state.json"]
    journal = json.loads((again.directory / "daily-state.json").read_text())
    assert journal["messages"]["m1"]["status"] == "complete"


def test_restoration_never_returns_a_token_or_consent(tmp_path):
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)
    again = conn.connect(tmp_path, A, now=T0 + dt.timedelta(days=30))
    restore(again, tmp_path, A)

    present = {p.name for p in again.directory.iterdir()}
    assert "token.enc.json" not in present
    assert "ai-drafting-approval.json" not in present
    assert "taxonomy-confirmation.json" not in present


def test_a_different_address_gets_nothing_back(tmp_path):
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)
    other = conn.connect(tmp_path, B, now=T0 + dt.timedelta(days=1))
    assert restorable(tmp_path, B) == []
    assert restore(other, tmp_path, B) == []


def test_a_mismatched_manifest_is_refused_even_at_the_right_path(tmp_path):
    """Isolates the hash check from the hash-derived path.

    Normally a different address resolves to a different directory, so the
    manifest check never runs. It is the second layer, and it matters when an
    archive is copied or a manifest swapped: the directory then exists for the
    wrong account, and only the recorded hash can say so.
    """
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)

    # Copy A's archive verbatim into the location B would look in.
    source = archive_path(tmp_path, A)
    target = archive_path(tmp_path, B)
    shutil.copytree(source, target)
    assert (target / arch.MANIFEST_FILE).exists(), "the fixture did not copy"

    assert restorable(tmp_path, B) == [], (
        "an archive belonging to another account was offered back"
    )
    other = conn.connect(tmp_path, B, now=T0 + dt.timedelta(days=1))
    assert restore(other, tmp_path, B) == []


def test_restored_files_are_owner_only(tmp_path):
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)
    again = conn.connect(tmp_path, A, now=T0 + dt.timedelta(days=30))
    restore(again, tmp_path, A)
    for name in ("account.json", "daily-state.json"):
        assert stat.S_IMODE(os.stat(again.directory / name).st_mode) == 0o600


def test_restoration_refuses_to_overwrite_live_state(tmp_path):
    """Restoring is for a fresh reconnection, not a rollback of live state."""
    first = _populated(tmp_path)
    disconnect(first, tmp_path, now=T0)
    again = conn.connect(tmp_path, A, now=T0 + dt.timedelta(days=30))
    again.directory.mkdir(parents=True, exist_ok=True)
    (again.directory / "daily-state.json").write_text(
        json.dumps({"version": 1, "messages": {"newer": {}}}), encoding="utf-8")

    with pytest.raises(ArchiveError, match="refusing to overwrite"):
        restore(again, tmp_path, A)


def test_restorable_is_empty_when_nothing_was_archived(tmp_path):
    assert restorable(tmp_path, A) == []
    assert read_manifest(tmp_path, A) is None


# ---------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------

def test_the_module_never_contacts_google():
    tree = ast.parse(Path("connection_archive.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("urllib", "requests", "socket", "http",
                      "gmail_auth", "googleapiclient", "gemini_client"):
        assert forbidden not in imported, (
            f"connection_archive imports {forbidden}; revocation is injected"
        )


def test_nothing_reads_a_token_back_from_an_archive():
    """There is no code path that could return a credential."""
    source = Path("connection_archive.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    restore_fn = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "restore"
    )
    rendered = ast.unparse(restore_fn)
    assert "token" not in rendered
    assert "RESTORABLE" in ast.unparse(tree), "restoration is not allowlisted"
