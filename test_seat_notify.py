"""Offline tests for the per-seat failure webhook.

A webhook leaves the machine, so it is held to a stricter standard than the
local status file: allowlisted counts and codes only, and never the account
address, a subject, an exception message, or a path.
"""
import ast
import json
from pathlib import Path

import pytest

import seat_notify
from seat_notify import (
    NotifyConfigError,
    PAYLOAD_FIELDS,
    build_payload,
    notify_seat_failure,
    validate_endpoint,
)


PRIVATE = (
    "coach@example.test",
    "PRIVATE SUBJECT MARKER",
    "PRIVATE BODY MARKER",
    "ya29.SECRETTOKEN",
    "/Users/someone/tokens/coach.json",
    "Traceback (most recent call last)",
)


def _status(**overrides):
    run = {
        "mode": "daily:apply",
        "outcome": "failed",
        "counts": {"scanned": 12, "drafted": 2, "failures": 3},
        "safe_error_codes": ["draft_write_failed"],
    }
    run.update(overrides)
    return {"version": 1, "last_run": run}


class _Sender:
    def __init__(self, result=True, raises=None):
        self.calls = []
        self.result = result
        self.raises = raises

    def __call__(self, url, body):
        self.calls.append((url, body))
        if self.raises:
            raise self.raises
        return self.result


# ---------------------------------------------------------------------
# What may leave the machine
# ---------------------------------------------------------------------

def test_payload_carries_only_allowlisted_fields():
    payload = build_payload("coach", 1, _status())
    assert set(payload) == PAYLOAD_FIELDS


def test_payload_shape_is_fixed_literally():
    """Written out rather than derived, so widening the allowlist fails."""
    payload = build_payload("coach", 1, _status())
    assert set(payload) == {
        "version", "seat", "outcome", "exit_code", "counts", "error_codes",
    }


def test_no_private_value_can_reach_the_wire():
    contaminated = {
        "version": 1,
        "account": "coach@example.test",
        "last_run": {
            "outcome": "failed",
            "mode": "daily:apply",
            "subject": "PRIVATE SUBJECT MARKER",
            "body": "PRIVATE BODY MARKER",
            "token_path": "/Users/someone/tokens/coach.json",
            "traceback": "Traceback (most recent call last)",
            "counts": {"scanned": 4, "PRIVATE SUBJECT MARKER": 9},
            "safe_error_codes": ["draft_write_failed", *PRIVATE],
        },
    }
    sender = _Sender()
    assert notify_seat_failure(
        "coach", "https://hooks.example.test/x", 1, contaminated, sender) is True
    _url, body = sender.calls[0]
    text = body.decode("utf-8")
    for marker in PRIVATE:
        assert marker not in text, f"a private value reached the wire: {marker!r}"
    assert "draft_write_failed" in text


def test_the_account_address_is_never_included():
    """The seat id is an operator-chosen label; the address is identity."""
    payload = build_payload("coach", 1, _status())
    assert payload["seat"] == "coach"
    assert "account" not in payload
    assert "@" not in json.dumps(payload)


def test_unknown_error_codes_are_dropped():
    payload = build_payload("coach", 1, _status(
        safe_error_codes=["draft_write_failed", "invented_code", 42]))
    assert payload["error_codes"] == ["draft_write_failed"]


def test_malformed_counts_degrade_to_zero():
    payload = build_payload("coach", 1, _status(
        counts={"scanned": -5, "drafted": True, "failures": "many",
                "labeled": 7}))
    assert payload["counts"]["labeled"] == 7
    for key in ("scanned", "drafted", "failures"):
        assert payload["counts"][key] == 0


def test_a_missing_status_document_still_produces_a_valid_notice():
    payload = build_payload("coach", 2, None)
    assert set(payload) == PAYLOAD_FIELDS
    assert payload["exit_code"] == 2
    assert payload["error_codes"] == []


# ---------------------------------------------------------------------
# Endpoint validation
# ---------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "http://hooks.example.test/x",
    "ftp://hooks.example.test/x",
    "file:///etc/passwd",
    "https://",
    "",
    None,
    "not a url",
])
def test_invalid_endpoints_are_refused(bad):
    with pytest.raises(NotifyConfigError):
        validate_endpoint(bad)


def test_https_endpoint_is_accepted():
    assert validate_endpoint(" https://hooks.example.test/x ") == \
        "https://hooks.example.test/x"


def test_a_plaintext_endpoint_sends_nothing():
    sender = _Sender()
    assert notify_seat_failure(
        "coach", "http://hooks.example.test/x", 1, _status(), sender) is False
    assert sender.calls == [], "a notice was sent over plaintext"


# ---------------------------------------------------------------------
# Failure must not replace the failure
# ---------------------------------------------------------------------

def test_a_raising_sender_is_reported_not_propagated():
    """This runs on an exception path; raising would hide the real error."""
    sender = _Sender(raises=OSError("network down"))
    assert notify_seat_failure(
        "coach", "https://hooks.example.test/x", 1, _status(), sender) is False


def test_an_unexpected_sender_exception_is_also_contained():
    sender = _Sender(raises=RuntimeError("something exotic"))
    assert notify_seat_failure(
        "coach", "https://hooks.example.test/x", 1, _status(), sender) is False


def test_a_rejecting_endpoint_reports_false():
    sender = _Sender(result=False)
    assert notify_seat_failure(
        "coach", "https://hooks.example.test/x", 1, _status(), sender) is False


def test_body_is_valid_json_with_a_version():
    sender = _Sender()
    notify_seat_failure("coach", "https://hooks.example.test/x", 1,
                        _status(), sender)
    document = json.loads(sender.calls[0][1].decode("utf-8"))
    assert document["version"] == seat_notify.PAYLOAD_VERSION
    assert document["outcome"] == "failed"


# ---------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------

def test_the_module_performs_no_gmail_operation():
    tree = ast.parse(Path("seat_notify.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("gmail_auth", "gemini_client", "googleapiclient",
                      "smtplib", "email"):
        assert forbidden not in imported, f"seat_notify imports {forbidden}"


def test_the_no_send_boundary_is_documented_as_the_reason():
    source = Path("seat_notify.py").read_text(encoding="utf-8")
    assert "must never send mail" in source
