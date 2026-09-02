"""Offline tests for protected campaign approval and private audit output."""
import json
import os

import pytest

import campaign
from campaign import (
    load_campaign_approval,
    select_targets,
)
from campaign_audit import audit_entry, build_report, write_report


def test_protected_label_real_run_refuses_before_gmail(monkeypatch, tmp_path):
    body = tmp_path / "body.txt"
    body.write_text("Coach-approved final body https://example.test")
    contacted = []
    monkeypatch.setattr(
        campaign, "get_gmail_service", lambda **_kwargs: contacted.append(True)
    )
    assert campaign.main(["YEAR_LABEL", str(body), "--yes"]) == 2
    assert contacted == []


def test_campaign_approval_is_account_label_bound_private_and_deduplicated(tmp_path):
    path = tmp_path / "approval.json"
    path.write_text(json.dumps({
        "version": 1,
        "account": "coach@example.edu",
        "label": "YEAR_LABEL",
        "approved_recipients": ["Recruit <r@example.test>"],
    }))
    assert load_campaign_approval(
        path, "YEAR_LABEL", "coach@example.edu"
    ) == {"r@example.test"}
    assert (path.stat().st_mode & 0o777) == 0o600

    with pytest.raises(ValueError, match="account"):
        load_campaign_approval(path, "YEAR_LABEL", "other@example.edu")
    with pytest.raises(ValueError, match="label"):
        load_campaign_approval(path, "Other", "coach@example.edu")

    path.write_text(json.dumps({
        "version": 1,
        "account": "coach@example.edu",
        "label": "YEAR_LABEL",
        "approved_recipients": ["old@example.test", "new@example.test"],
    }))
    with pytest.raises(ValueError, match="duplicate canonical"):
        load_campaign_approval(
            path, "YEAR_LABEL", "coach@example.edu",
            aliases={"old@example.test": "new@example.test"},
        )


def test_allowlist_intersects_after_exclusions_and_limit():
    by_sender = {
        "a@example.test": {"sender": "a@example.test", "internal_date": 3},
        "b@example.test": {"sender": "b@example.test", "internal_date": 2},
        "c@example.test": {"sender": "c@example.test", "internal_date": 1},
    }
    eligible, targets = select_targets(
        by_sender,
        exclusions={"b@example.test"},
        approved={"a@example.test", "b@example.test"},
        limit=1,
    )
    assert [item["sender"] for item in eligible] == ["a@example.test"]
    assert targets == eligible


def test_audit_report_is_private_and_never_contains_message_content(tmp_path):
    body_marker = "PRIVATE-BODY-MUST-NOT-APPEAR"
    model_marker = "MODEL-REASON-MUST-NOT-APPEAR"
    record = {
        "message_id": "m1",
        "sender": "recruit@example.test",
        "reply_address": "recruit@example.test",
        "delivery_safety": {
            "status": "normal", "reason_codes": [],
        },
    }
    plan = {
        "classification": {
            "actionable": True,
            "local_grad_year": "2027",
            "local_evidence_codes": ["class_of_year"],
            "reason": model_marker,
        },
        "category": "recruit_intro",
        "sender_type": "recruit",
        "confidence": "high",
        "grad_year": "2027",
        "classification_called": True,
        "email": {"body": body_marker},
    }
    entry = audit_entry(record, plan)
    report = build_report("coach@example.edu", "YEAR_LABEL", [entry])
    path = tmp_path / "reports" / "audit.json"
    write_report(path, report)
    text = path.read_text(encoding="utf-8")
    assert body_marker not in text
    assert model_marker not in text
    assert "recruit@example.test" in text
    assert (path.stat().st_mode & 0o777) == 0o600
    assert (path.parent.stat().st_mode & 0o777) == 0o700
    with pytest.raises(FileExistsError):
        write_report(path, report)


def test_audit_automated_sender_is_excluded_without_model_data():
    entry = audit_entry({
        "message_id": "m1",
        "sender": "no-reply@example.test",
        "reply_address": "",
        "delivery_safety": {
            "status": "automated", "reason_codes": ["automated_sender"],
        },
    })
    assert entry["recommendation"] == "exclude"
    assert entry["model"]["used"] is False
    assert entry["recipient"] == "no-reply@example.test"


# --------------------------------------------------------------------
# Rollback scope: undo must act on exactly the ids this program logged.
#
# trash_drafts is well covered, but nothing previously asserted where
# run_undo gets its ids. Replacing `load_draft_ids(log_path)` with a
# hardcoded list passed the whole suite, which means a rollback that
# enumerated the mailbox instead of reading the log would not have been
# caught - and that would trash drafts the coach wrote by hand.
# --------------------------------------------------------------------

class _UndoFakeCall:
    def __init__(self, result=None, error=None):
        self._result, self._error = result, error

    def execute(self):
        if self._error:
            raise self._error
        return self._result


class _UndoFakeGmail:
    """Holds both program-created and manual drafts, and records every
    message id that is trashed."""

    def __init__(self, drafts):
        self._drafts = drafts          # draft_id -> message_id
        self.trashed = []
        self.deleted = []

    def users(self):
        return self

    def drafts(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id, format=None):
        if id not in self._drafts:
            import googleapiclient.errors

            class _R:
                status, reason = 404, "Not Found"
            return _UndoFakeCall(
                error=googleapiclient.errors.HttpError(_R(), b"{}")
            )
        return _UndoFakeCall({"id": id, "message": {"id": self._drafts[id]}})

    def trash(self, userId, id):
        self.trashed.append(id)
        return _UndoFakeCall({"id": id})

    def delete(self, userId, id):
        self.deleted.append(id)
        return _UndoFakeCall({})


def test_undo_touches_only_ids_recorded_in_the_log(tmp_path, monkeypatch):
    import campaign as campaign_module
    from campaign import DraftLog, QuotaThrottle, run_undo

    monkeypatch.setattr(campaign_module, "DRAFT_LOG_DIR", str(tmp_path))

    mailbox = {
        "prog-1": "msg-prog-1",
        "prog-2": "msg-prog-2",
        "MANUAL-coach-draft": "msg-manual",   # never logged by this program
    }
    service = _UndoFakeGmail(mailbox)

    log_path = str(tmp_path / "campaign-run.log")
    with DraftLog(log_path, ["seeded run"]) as log:
        log.record("prog-1")
        log.record("prog-2")

    run_undo(service, log_path, QuotaThrottle(units_per_second=100_000),
             assume_yes=True)

    assert service.trashed == ["msg-prog-1", "msg-prog-2"], (
        "undo trashed something other than the logged drafts"
    )
    assert "msg-manual" not in service.trashed, (
        "undo trashed a manual draft that this program never created"
    )
    assert service.deleted == [], "undo must trash, never permanently delete"


def test_undo_on_an_empty_log_touches_nothing(tmp_path, monkeypatch):
    import campaign as campaign_module
    from campaign import QuotaThrottle, run_undo

    monkeypatch.setattr(campaign_module, "DRAFT_LOG_DIR", str(tmp_path))
    service = _UndoFakeGmail({"MANUAL-coach-draft": "msg-manual"})

    log_path = tmp_path / "empty.log"
    log_path.write_text("# header only, no ids\n")

    run_undo(service, str(log_path), QuotaThrottle(units_per_second=100_000),
             assume_yes=True)

    assert service.trashed == []
    assert service.deleted == []


def test_undo_dry_run_changes_nothing(tmp_path, monkeypatch):
    import campaign as campaign_module
    from campaign import DraftLog, QuotaThrottle, run_undo

    monkeypatch.setattr(campaign_module, "DRAFT_LOG_DIR", str(tmp_path))
    service = _UndoFakeGmail({"prog-1": "msg-prog-1"})

    log_path = str(tmp_path / "run.log")
    with DraftLog(log_path) as log:
        log.record("prog-1")

    run_undo(service, log_path, QuotaThrottle(units_per_second=100_000),
             dry_run=True, assume_yes=True)

    assert service.trashed == [], "dry run must not trash anything"
