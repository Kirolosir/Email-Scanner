"""Offline tests for the single-connection state machine.

The rules being pinned: one account at a time, hand-off is explicit, a lapsed
token does not vacate the slot, and a refusal writes nothing at all.
"""
import ast
import datetime as dt
import json
import os
import stat
from pathlib import Path

import pytest

import connection as conn
from connection import (
    ConnectionConfigError,
    ConnectionOccupied,
    connect,
    current,
    normalize_account,
    occupied_by,
    record_path,
    same_account,
    update_settings,
)


A = "coach@example.test"
B = "someone.else@example.test"
T0 = dt.datetime(2026, 9, 6, 18, 0, tzinfo=dt.timezone.utc)


def _snapshot(root):
    """Every file under root with its bytes, for proving nothing changed."""
    found = {}
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            found[str(path.relative_to(root))] = path.read_bytes()
    return found


# ---------------------------------------------------------------------
# Vacant -> connected
# ---------------------------------------------------------------------

def test_a_vacant_deployment_reports_no_occupant(tmp_path):
    assert current(tmp_path) is None
    assert occupied_by(tmp_path) is None


def test_connecting_to_a_vacant_deployment_records_both_timestamps(tmp_path):
    established = connect(tmp_path, A, timezone="America/New_York",
                          run_at="18:00", now=T0)
    assert established.account == A
    assert established.connected_at == established.last_authorized_at
    assert occupied_by(tmp_path) == A


def test_a_new_connection_defaults_to_eastern_time(tmp_path):
    established = connect(tmp_path, A, now=T0)

    assert established.timezone_name == "America/New_York"
    assert established.run_at == "18:00"


def test_the_record_is_owner_only(tmp_path):
    connect(tmp_path, A, now=T0)
    assert stat.S_IMODE(os.stat(record_path(tmp_path)).st_mode) == 0o600


def test_paths_are_derived_from_the_root_never_the_address(tmp_path):
    """No account-derived path means nothing outside can steer a write."""
    established = connect(tmp_path, A, now=T0)
    assert established.directory == Path(tmp_path).resolve() / "active"
    for path in (established.state_path, established.status_path,
                 established.review_dir, established.lock_dir):
        assert str(path).startswith(str(established.directory))
        assert "coach" not in str(path)


# ---------------------------------------------------------------------
# The refusal rule
# ---------------------------------------------------------------------

def test_a_different_account_is_refused_and_names_the_occupant(tmp_path):
    connect(tmp_path, A, now=T0)
    with pytest.raises(ConnectionOccupied) as caught:
        connect(tmp_path, B, now=T0 + dt.timedelta(days=1))
    assert caught.value.account == A
    assert A in str(caught.value)
    assert occupied_by(tmp_path) == A, "the occupant was replaced"


def test_a_refused_connect_writes_absolutely_nothing(tmp_path):
    """A half-written replacement is a silent replacement with extra steps."""
    connect(tmp_path, A, timezone="America/New_York", run_at="18:00", now=T0)
    established = current(tmp_path)
    established.directory.mkdir(parents=True, exist_ok=True)
    established.state_path.write_text('{"version": 1, "messages": {}}',
                                      encoding="utf-8")

    before = _snapshot(tmp_path)
    with pytest.raises(ConnectionOccupied):
        connect(tmp_path, B, timezone="UTC", run_at="06:00",
                now=T0 + dt.timedelta(days=2))
    assert _snapshot(tmp_path) == before


def test_an_expired_or_absent_token_does_not_vacate_the_slot(tmp_path):
    """Occupancy is the record, never the token.

    Testing-mode tokens lapse weekly. If that freed the connection, a
    different account could inherit somebody's configuration and journal
    simply by turning up on a Tuesday.
    """
    connect(tmp_path, A, now=T0)
    token = current(tmp_path).directory / "token.enc.json"
    assert not token.exists(), "no token was ever stored in this test"

    with pytest.raises(ConnectionOccupied):
        connect(tmp_path, B, now=T0 + dt.timedelta(days=30))
    assert occupied_by(tmp_path) == A


# ---------------------------------------------------------------------
# Re-authorisation of the same account
# ---------------------------------------------------------------------

def test_the_same_account_may_reauthorise(tmp_path):
    connect(tmp_path, A, now=T0)
    later = T0 + dt.timedelta(days=7)
    refreshed = connect(tmp_path, A, now=later)
    assert refreshed.account == A
    assert refreshed.last_authorized_at == later.isoformat(timespec="seconds")
    assert refreshed.connected_at == T0.isoformat(timespec="seconds"), (
        "the original connection date was overwritten"
    )


@pytest.mark.parametrize("spelling", [
    "COACH@example.test", "  coach@example.test  ", "Coach@Example.Test",
])
def test_reauthorisation_recognises_the_same_address_however_spelled(
        tmp_path, spelling):
    connect(tmp_path, A, now=T0)
    connect(tmp_path, spelling, now=T0 + dt.timedelta(days=7))
    assert occupied_by(tmp_path) == A


def test_reauthorisation_does_not_change_the_schedule_or_limits(tmp_path):
    """A weekly token refresh must not quietly alter how the run behaves."""
    connect(tmp_path, A, timezone="America/New_York", run_at="18:00", now=T0,
            limits={"max_drafts": 2})
    connect(tmp_path, A, timezone="UTC", run_at="03:00",
            now=T0 + dt.timedelta(days=7), limits={"max_drafts": 99})
    after = current(tmp_path)
    assert after.timezone_name == "America/New_York"
    assert after.run_at == "18:00"
    assert after.max_drafts == 2


def test_reauthorisation_leaves_every_artifact_untouched(tmp_path):
    connect(tmp_path, A, now=T0)
    established = current(tmp_path)
    established.review_dir.mkdir(parents=True, exist_ok=True)
    established.state_path.write_text('{"version": 1, "messages": {"m": {}}}',
                                      encoding="utf-8")
    (established.review_dir / "r.json").write_text("{}", encoding="utf-8")

    connect(tmp_path, A, now=T0 + dt.timedelta(days=7))

    assert json.loads(established.state_path.read_text())["messages"] == {"m": {}}
    assert (established.review_dir / "r.json").exists()


# ---------------------------------------------------------------------
# Record validation
# ---------------------------------------------------------------------

def test_an_unreadable_record_raises_rather_than_reading_as_vacant(tmp_path):
    """Vacancy on a damaged record is how a stranger takes over silently."""
    record_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    record_path(tmp_path).write_text("{{{ not json", encoding="utf-8")
    with pytest.raises(ConnectionConfigError, match="not valid JSON"):
        current(tmp_path)


@pytest.mark.parametrize("mutation,message", [
    ({"account": "not-an-address"}, "invalid account"),
    ({"run_at": "25:00"}, "run_at"),
    ({"timezone": "Mars/Olympus"}, "unknown timezone"),
    ({"version": 2}, "version 1"),
    ({"max_drafts": -1}, "nonnegative"),
    ({"enabled": "yes"}, "true or false"),
    ({"unexpected_key": 1}, "unsupported connection keys"),
])
def test_invalid_records_are_refused(tmp_path, mutation, message):
    connect(tmp_path, A, now=T0)
    document = json.loads(record_path(tmp_path).read_text())
    document.update(mutation)
    record_path(tmp_path).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ConnectionConfigError, match=message):
        current(tmp_path)


def test_connecting_an_invalid_address_is_refused(tmp_path):
    with pytest.raises(ConnectionConfigError, match="not valid"):
        connect(tmp_path, "nonsense", now=T0)
    assert current(tmp_path) is None


def test_settings_update_preserves_identity_and_authorization(tmp_path):
    first = connect(tmp_path, A, now=T0)
    updated = update_settings(
        tmp_path, A, timezone="America/New_York", run_at="19:30",
        limits={"max_scan": 40, "limit": 30, "max_drafts": 8},
    )
    assert updated.account == A
    assert updated.connected_at == first.connected_at
    assert updated.last_authorized_at == first.last_authorized_at
    assert updated.timezone_name == "America/New_York"
    assert updated.run_at == "19:30"
    assert (updated.max_scan, updated.limit, updated.max_drafts) == (40, 30, 8)


def test_settings_cannot_create_or_take_over_a_connection(tmp_path):
    with pytest.raises(ConnectionConfigError, match="no account"):
        update_settings(tmp_path, A, run_at="19:00")
    connect(tmp_path, A, now=T0)
    with pytest.raises(ConnectionOccupied):
        update_settings(tmp_path, B, run_at="19:00")
    assert current(tmp_path).account == A


def test_settings_validate_before_persisting(tmp_path):
    connect(tmp_path, A, now=T0)
    before = _snapshot(tmp_path)
    with pytest.raises(ConnectionConfigError, match="run_at"):
        update_settings(tmp_path, A, run_at="midnight")
    assert _snapshot(tmp_path) == before


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def test_account_comparison_ignores_case_and_surrounding_space():
    assert same_account("A@b.test", " a@B.TEST ") is True
    assert same_account("a@b.test", "c@d.test") is False
    assert same_account("", "a@b.test") is False
    assert normalize_account("  A@B.test ") == "a@b.test"


# ---------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------

def test_the_module_neither_reaches_the_network_nor_runs_a_job():
    tree = ast.parse(Path("connection.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("gmail_auth", "gemini_client", "googleapiclient",
                      "urllib", "requests", "socket", "subprocess",
                      "daily_triage", "triage"):
        assert forbidden not in imported, f"connection imports {forbidden}"


def test_no_roster_machinery_survives():
    """The multi-seat model is gone as code, not merely unused.

    Checked over identifiers rather than raw text: the module docstring
    legitimately explains what was removed and why, and prose describing a
    deleted concept is documentation, not surviving machinery.
    """
    tree = ast.parse(Path("connection.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
    for gone in ("MAX_SEATS", "roster", "load_roster", "seats",
                 "enabled_seats", "find_seat", "due_seats"):
        assert gone not in names, f"roster machinery survives as code: {gone!r}"
    assert not Path("seats.py").exists()
    assert not Path("seat_tokens.py").exists()
    assert not Path("seat_schedule.py").exists()
