"""Offline tests for expected-expiry surfacing.

The rules being pinned: the seven-day window is computed from the moment the
token was issued, the result is always labelled a prediction and always
carries the evidence beside it, and a run that succeeded after the predicted
lapse outranks the prediction rather than being contradicted by it.
"""
import ast
import datetime as dt
from pathlib import Path

import pytest

import connection as conn
import connection_expiry as expiry
from connection_expiry import (
    BASIS,
    EXPIRED,
    EXPIRING,
    EXPIRING_SOON_DAYS,
    HEALTHY,
    TESTING_MODE_TOKEN_LIFETIME_DAYS,
    UNKNOWN,
    expected_expiry,
    expiry_state,
    should_attempt,
)
from local_notifier import SAFE_ERROR_CODES


A = "coach@example.test"
T0 = dt.datetime(2026, 9, 6, 18, 0, tzinfo=dt.timezone.utc)


def _connection(tmp_path, now=T0):
    return conn.connect(tmp_path, A, timezone="America/New_York",
                        run_at="18:00", now=now)


def _at(days, hours=0):
    return T0 + dt.timedelta(days=days, hours=hours)


# ---------------------------------------------------------------------
# The window itself
# ---------------------------------------------------------------------

def test_expiry_is_seven_days_from_the_moment_the_token_was_issued(tmp_path):
    established = _connection(tmp_path)
    assert expected_expiry(established) == T0 + dt.timedelta(days=7)


def test_reauthorising_resets_the_window(tmp_path):
    """last_authorized_at IS the issue time, so a refresh moves the clock."""
    _connection(tmp_path)
    refreshed = conn.connect(tmp_path, A, now=_at(6))
    assert expected_expiry(refreshed) == _at(6) + dt.timedelta(days=7)


def test_the_documented_lifetime_is_seven_days():
    assert TESTING_MODE_TOKEN_LIFETIME_DAYS == 7


# ---------------------------------------------------------------------
# The three states
# ---------------------------------------------------------------------

def test_a_fresh_connection_is_healthy(tmp_path):
    state = expiry_state(_connection(tmp_path), _at(1))
    assert state["state"] == HEALTHY
    assert "expected to last" in state["summary"]


def test_it_warns_before_it_breaks(tmp_path):
    """Two days of warning is the whole point of predicting at all."""
    state = expiry_state(_connection(tmp_path), _at(5, 1))
    assert state["state"] == EXPIRING
    assert 0 < state["days_remaining"] <= EXPIRING_SOON_DAYS


def test_past_the_window_reads_as_reconnect_required(tmp_path):
    state = expiry_state(_connection(tmp_path), _at(8))
    assert state["state"] == EXPIRED
    assert "reconnect required" in state["summary"]
    assert state["days_remaining"] < 0


def test_the_warning_boundary_is_respected_exactly(tmp_path):
    established = _connection(tmp_path)
    just_inside = expiry_state(established, _at(7 - EXPIRING_SOON_DAYS, -1))
    just_outside = expiry_state(established, _at(7 - EXPIRING_SOON_DAYS, 1))
    assert just_inside["state"] == HEALTHY
    assert just_outside["state"] == EXPIRING


def test_the_last_day_is_described_in_hours_not_zero_days(tmp_path):
    state = expiry_state(_connection(tmp_path), _at(6, 18))
    assert "under a day" in state["summary"]


def test_an_unknown_issue_time_is_unknown_not_healthy(tmp_path):
    """Absence of a timestamp must not read as a fresh connection."""
    established = _connection(tmp_path)
    established.last_authorized_at = ""
    state = expiry_state(established, _at(1))
    assert state["state"] == UNKNOWN
    assert state["expected_expiry"] is None
    assert "unknown" in state["summary"].lower()


# ---------------------------------------------------------------------
# Prediction versus evidence
# ---------------------------------------------------------------------

def test_every_result_declares_itself_a_prediction(tmp_path):
    established = _connection(tmp_path)
    for now in (_at(1), _at(6), _at(9)):
        assert expiry_state(established, now)["basis"] == BASIS == "prediction"


def test_the_evidence_is_always_carried_beside_the_estimate(tmp_path):
    """An interface must not be able to show the countdown on its own."""
    established = _connection(tmp_path)
    run = _at(3).isoformat(timespec="seconds")
    state = expiry_state(established, _at(4), last_successful_run=run)
    assert state["last_successful_run"] == run
    assert "last_successful_run" in state


def test_a_run_after_the_predicted_lapse_outranks_the_prediction(tmp_path):
    """The estimate was wrong, not the connection."""
    established = _connection(tmp_path)
    later_run = _at(9).isoformat(timespec="seconds")
    state = expiry_state(established, _at(10), last_successful_run=later_run)

    assert state["state"] == HEALTHY
    assert state["evidence_overrides_prediction"] is True
    assert "the estimate was wrong" in state["summary"]


def test_a_run_before_the_lapse_does_not_override_it(tmp_path):
    established = _connection(tmp_path)
    earlier_run = _at(3).isoformat(timespec="seconds")
    state = expiry_state(established, _at(9), last_successful_run=earlier_run)
    assert state["state"] == EXPIRED
    assert state["evidence_overrides_prediction"] is False


def test_an_unparseable_run_timestamp_is_ignored_not_trusted(tmp_path):
    state = expiry_state(_connection(tmp_path), _at(9),
                         last_successful_run="not-a-date")
    assert state["state"] == EXPIRED
    assert state["last_successful_run"] is None


# ---------------------------------------------------------------------
# Whether to attempt a run
# ---------------------------------------------------------------------

def test_a_healthy_connection_is_attempted(tmp_path):
    attempt, _state = should_attempt(_connection(tmp_path), _at(1))
    assert attempt is True


def test_an_expiring_connection_is_still_attempted(tmp_path):
    """Warning is not stopping. It still works until it does not."""
    attempt, state = should_attempt(_connection(tmp_path), _at(6))
    assert attempt is True and state["state"] == EXPIRING


def test_an_expired_connection_is_not_attempted(tmp_path):
    attempt, state = should_attempt(_connection(tmp_path), _at(9))
    assert attempt is False and state["state"] == EXPIRED


def test_a_token_outliving_the_window_is_never_locked_out_by_its_estimate(
        tmp_path):
    """The escape hatch that keeps a wrong prediction from becoming a trap."""
    established = _connection(tmp_path)
    proof = _at(9).isoformat(timespec="seconds")
    attempt, state = should_attempt(established, _at(10),
                                    last_successful_run=proof)
    assert attempt is True
    assert state["evidence_overrides_prediction"] is True


def test_an_unknown_age_is_still_attempted(tmp_path):
    """Not knowing is not the same as knowing it is dead."""
    established = _connection(tmp_path)
    established.last_authorized_at = ""
    attempt, state = should_attempt(established, _at(1))
    assert attempt is True and state["state"] == UNKNOWN


# ---------------------------------------------------------------------
# Vocabulary and boundaries
# ---------------------------------------------------------------------

def test_a_lapse_has_its_own_safe_error_code():
    """Distinguishable at a glance from a run that actually broke."""
    assert "connection_expired" in SAFE_ERROR_CODES


def test_the_module_observes_nothing_and_contacts_nobody():
    tree = ast.parse(Path("connection_expiry.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("urllib", "requests", "socket", "http", "gmail_auth",
                      "googleapiclient", "google", "subprocess"):
        assert forbidden not in imported, (
            f"connection_expiry imports {forbidden}; it predicts, it does not "
            "verify"
        )


def test_nothing_can_declare_the_state_observed():
    """basis is a constant; there is no branch that could claim otherwise."""
    source = Path("connection_expiry.py").read_text(encoding="utf-8")
    assert 'BASIS = "prediction"' in source
    assert '"observed"' not in source
