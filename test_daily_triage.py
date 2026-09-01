"""Offline daily-triage tests using only fake Gmail and stub classifiers."""
import datetime as dt
import base64
import json
import os

import pytest

from daily_triage import (
    DailyState,
    add_daily_review_policy,
    build_daily_query,
    build_initial_query,
    execute_daily_plan,
    list_existing_draft_threads,
    reconcile_existing_drafts,
)
import daily_triage
from gmail_common import QuotaThrottle, list_message_ids_by_query
from gmail_labeler import LabelDecision
from triage import plan_message
from triage_config import TriageLabelConfig
from private_runtime import ExclusiveRunLock, LOCKED_EXIT_CODE


CONFIG = TriageLabelConfig(
    years={"2027": "2027B"},
    categories={
        "recruit_intro": "Intro",
        "parent": "Parent",
        "other_coach": "Coach",
        "other": "Other",
    },
    system={"needs_review": "Needs Review", "processed": "Processed"},
)
ACCOUNT_LABELS = {
    "2027B": "Y27", "Intro": "C1", "Parent": "C2", "Coach": "C3",
    "Other": "C4", "Needs Review": "NR", "Processed": "DONE",
}


def _email(**overrides):
    result = {
        "message_id": "m1",
        "from": "person@example.test",
        "subject": "Introduction",
        "body": "I am a Class of 2027 recruit. Offline seeded body.",
        "thread_id": "t1",
        "rfc_message_id": "<m1@example.test>",
        "label_names": [],
    }
    result.update(overrides)
    return result


def _classification(category, sender_type, year="2027", valid=True):
    return {
        "category": category,
        "grad_year": year,
        "sender_type": sender_type,
        "confidence": "high",
        "evidence": "offline deterministic fixture",
        "reason": "offline seeded reason",
        "valid": valid,
    }


@pytest.mark.parametrize("builder,value,fragment", [
    (build_initial_query, 2, "newer_than:2m"),
    (build_daily_query, 3, "newer_than:3d"),
])
def test_queries_are_inbox_only_and_exclude_unsafe_mailboxes(builder, value, fragment):
    query = builder(value)
    assert fragment in query
    for clause in ("in:inbox", "-in:spam", "-in:trash", "-in:sent", "-in:drafts"):
        assert clause in query


def test_only_actual_recruit_gets_2027b():
    templates = {
        "recruit_intro_2027": "approved recruit reply",
        "parent": "approved parent reply",
        "other_coach": "approved coach reply",
    }
    cases = [
        ("recruit_intro", "recruit", {"Intro", "2027B"}),
        ("parent", "parent", {"Parent"}),
        ("other_coach", "coach", {"Coach"}),
    ]
    for category, sender_type, expected in cases:
        plan = plan_message(
            _email(), templates, CONFIG.years, CONFIG.categories, False,
            classifier=lambda _email, c=category, s=sender_type: _classification(c, s),
        )
        assert set(plan["decision"].add) == expected


def test_unknown_or_missing_template_routes_to_needs_review_without_draft():
    unknown = plan_message(
        _email(), {}, CONFIG.years, CONFIG.categories, False,
        classifier=lambda _: _classification("unknown", "unknown", "unknown", False),
    )
    add_daily_review_policy(unknown, CONFIG)
    assert unknown["template"] is None
    assert "Needs Review" in unknown["decision"].add

    missing = plan_message(
        _email(), {}, CONFIG.years, CONFIG.categories, False,
        classifier=lambda _: _classification("parent", "parent"),
    )
    add_daily_review_policy(missing, CONFIG)
    assert missing["template"] is None
    assert "Needs Review" in missing["decision"].add


def test_model_text_can_never_become_a_label_name():
    injected = plan_message(
        _email(), {}, CONFIG.years, CONFIG.categories, False,
        classifier=lambda _: _classification(
            "Attacker/Invented Label", "recruit", "2027", True
        ),
    )
    add_daily_review_policy(injected, CONFIG)
    assert "Attacker/Invented Label" not in injected["decision"].add
    assert set(injected["decision"].add) == {"Needs Review"}


def test_inconsistent_sender_and_category_gets_review_only():
    inconsistent = plan_message(
        _email(), {"recruit_intro_2027": "approved"},
        CONFIG.years, CONFIG.categories, False,
        classifier=lambda _: _classification("recruit_intro", "parent", "2027"),
    )
    add_daily_review_policy(inconsistent, CONFIG)
    assert inconsistent["classification"]["valid"] is False
    assert inconsistent["template"] is None
    assert set(inconsistent["decision"].add) == {"Needs Review"}


class _Call:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def execute(self):
        if self.error:
            raise self.error
        return self.result


class _ExecutionGmail:
    def __init__(self, fail_processed_once=False):
        self.modify_calls = []
        self.create_calls = []
        self.fail_processed_once = fail_processed_once

    def users(self): return self
    def messages(self): return self
    def drafts(self): return self

    def modify(self, userId, id, body):
        self.modify_calls.append(body)
        if (self.fail_processed_once
                and body.get("addLabelIds") == ["DONE"]):
            self.fail_processed_once = False
            return _Call(error=ConnectionError("offline interruption"))
        return _Call({"id": id})

    def create(self, userId, body):
        self.create_calls.append(body)
        return _Call({"id": "draft-1", "message": {"threadId": "t1"}})


class _Log:
    def __init__(self):
        self.ids = []

    def record(self, draft_id):
        self.ids.append(draft_id)


def _execution_plan():
    return {
        "email": _email(),
        "decision": LabelDecision(add=["Intro", "2027B"]),
        "template": "approved reply",
        "processed_label": "Processed",
    }


def test_interruption_after_draft_recovers_without_duplicate(tmp_path):
    service = _ExecutionGmail(fail_processed_once=True)
    state = DailyState(tmp_path / "state" / "daily.json")
    log = _Log()
    throttle = QuotaThrottle(100_000)

    _added, draft_id, errors = execute_daily_plan(
        service, _execution_plan(), ACCOUNT_LABELS, throttle, log, state, {}
    )
    assert draft_id == "draft-1"
    assert errors and "processed label failed" in errors[0]
    assert state.record_for("m1")["status"] == "draft_created"
    assert len(service.create_calls) == 1
    assert log.ids == ["draft-1"]

    restarted = DailyState(tmp_path / "state" / "daily.json").load()
    _added, draft_id, errors = execute_daily_plan(
        service, _execution_plan(), ACCOUNT_LABELS, throttle, log, restarted, {}
    )
    assert errors == []
    assert draft_id == "draft-1"
    assert restarted.record_for("m1")["status"] == "complete"
    assert len(service.create_calls) == 1
    assert log.ids == ["draft-1"]


def test_existing_thread_draft_is_not_adopted_or_created(tmp_path):
    service = _ExecutionGmail()
    state = DailyState(tmp_path / "state.json")
    log = _Log()
    _added, draft_id, errors = execute_daily_plan(
        service, _execution_plan(), ACCOUNT_LABELS,
        QuotaThrottle(100_000), log, state, {"t1": "existing-draft"},
    )
    assert errors == ["existing_manual_draft"]
    assert draft_id == ""
    assert service.create_calls == []
    assert log.ids == [], "a pre-existing/manual draft must never enter rollback log"
    assert state.record_for("m1") == {}, "manual draft must not become program-owned"


def test_manual_draft_reconciliation_marks_needs_review_without_rollback_owner(tmp_path):
    plan = _execution_plan()
    plan.update({
        "template_key": "recruit_intro_2027",
        "draft_skip": None,
        "needs_review": False,
        "review_reasons": [],
    })
    state = DailyState(tmp_path / "state.json")
    reconcile_existing_drafts([plan], state, {"t1": "manual-draft"}, CONFIG)
    assert plan["template"] is None
    assert plan["existing_manual_draft"] is True
    assert "Needs Review" in plan["decision"].add
    assert state.record_for("m1") == {}


def test_daily_state_is_private_atomic_and_corruption_blocks(tmp_path):
    path = tmp_path / "private" / "state.json"
    state = DailyState(path)
    state.record_draft("m1", "t1", "d1")
    assert stat_mode(path) == 0o600
    assert stat_mode(path.parent) == 0o700
    assert DailyState(path).load().record_for("m1")["draft_id"] == "d1"
    text = path.read_text(encoding="utf-8")
    assert "offline seeded body" not in text
    assert "person@example.test" not in text

    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to reset"):
        DailyState(path).load()


def test_daily_same_day_guard_contacts_no_service(monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    state = DailyState(state_path)
    state.mark_daily_complete(dt.datetime.now(daily_triage.LOCAL_TIMEZONE).date())
    monkeypatch.setattr(
        daily_triage, "get_gmail_service",
        lambda: (_ for _ in ()).throw(AssertionError("must not contact Gmail")),
    )
    result = daily_triage.main([
        "daily", "--state-path", str(state_path), "--dry-run",
    ])
    assert result == 0


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


class _PagedMessages:
    def __init__(self):
        self.calls = []

    def users(self): return self
    def messages(self): return self

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["pageToken"] is None:
            return _Call({"messages": [{"id": "m1"}], "nextPageToken": "p2"})
        return _Call({"messages": [{"id": "m2"}]})


def test_query_listing_paginates_and_preserves_reviewed_query():
    service = _PagedMessages()
    query = build_initial_query()
    ids = list_message_ids_by_query(
        service, query, QuotaThrottle(100_000), progress=False
    )
    assert ids == ["m1", "m2"]
    assert [call["q"] for call in service.calls] == [query, query]


class _PagedDrafts:
    def __init__(self):
        self.calls = []

    def users(self): return self
    def drafts(self): return self

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["pageToken"] is None:
            return _Call({
                "drafts": [{"id": "d1", "message": {"threadId": "t1"}}],
                "nextPageToken": "p2",
            })
        return _Call({"drafts": [{"id": "d2", "message": {"threadId": "t2"}}]})


def test_existing_draft_scan_paginates_without_reading_bodies():
    service = _PagedDrafts()
    assert list_existing_draft_threads(service, QuotaThrottle(100_000)) == {
        "t1": "d1", "t2": "d2",
    }
    assert len(service.calls) == 2


class _MainFakeGmail:
    def __init__(self):
        from triage_config import load_triage_label_config
        config = load_triage_label_config("label-config.example.json")
        self.labels_by_name = {
            name: f"L{index}" for index, name in enumerate(config.all_names)
        }
        body = base64.urlsafe_b64encode(
            b"I am in the Class of 2027. PRIVATE BODY MARKER"
        ).decode().rstrip("=")
        self.message = {
            "id": "private-message-id", "threadId": "private-thread-id",
            "labelIds": [],
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "private-sender@example.test"},
                    {"name": "Subject", "value": "PRIVATE SUBJECT MARKER"},
                    {"name": "Message-ID", "value": "<private@example.test>"},
                ],
                "body": {"data": body},
            },
        }
        self.resource = None
        self.modify_calls = []
        self.create_calls = []

    def users(self): return self
    def labels(self): self.resource = "labels"; return self
    def messages(self): self.resource = "messages"; return self
    def drafts(self): self.resource = "drafts"; return self

    def getProfile(self, userId):
        return _Call({"emailAddress": "coach@example.edu"})

    def list(self, **kwargs):
        if self.resource == "labels":
            return _Call({"labels": [
                {"name": name, "id": label_id}
                for name, label_id in self.labels_by_name.items()
            ]})
        if self.resource == "drafts":
            return _Call({"drafts": []})
        return _Call({"messages": [{"id": self.message["id"]}]})

    def get(self, **kwargs):
        return _Call(self.message)

    def modify(self, **kwargs):
        self.modify_calls.append(kwargs)
        return _Call({})

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return _Call({"id": "d1"})


def _high_recruit(_email):
    return {
        "category": "recruit_intro", "grad_year": "2027",
        "sender_type": "recruit", "confidence": "high",
        "evidence": "offline", "reason": "PRIVATE MODEL REASON", "valid": True,
    }


def test_scheduled_dry_run_redacts_message_data_and_writes_private_status(
        monkeypatch, tmp_path, capsys):
    service = _MainFakeGmail()
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_kwargs: service)
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "recruit_intro_2027.txt").write_text("approved offline reply")
    state_path = tmp_path / "state" / "daily.json"
    result = daily_triage.main([
        "initial", "--state-path", str(state_path),
        "--templates", str(templates), "--scheduled", "--dry-run",
    ], classifier=_high_recruit)
    assert result == 0
    output = capsys.readouterr().out
    for private in (
        "PRIVATE SUBJECT MARKER", "private-sender@example.test",
        "PRIVATE BODY MARKER", "PRIVATE MODEL REASON",
    ):
        assert private not in output
    assert service.modify_calls == [] and service.create_calls == []
    status_path = state_path.with_name("daily-status.json")
    status_text = status_path.read_text(encoding="utf-8")
    assert "PRIVATE" not in status_text and "@example" not in status_text
    assert (status_path.stat().st_mode & 0o777) == 0o600


def test_estimate_only_calls_no_classifier_or_gmail_writes(
        monkeypatch, tmp_path, capsys):
    service = _MainFakeGmail()
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_kwargs: service)
    calls = []
    result = daily_triage.main([
        "initial", "--state-path", str(tmp_path / "state.json"),
        "--estimate-only", "--scheduled",
    ], classifier=lambda email: calls.append(email))
    assert result == 0
    assert calls == []
    assert service.modify_calls == [] and service.create_calls == []
    assert "zero Gemini calls" in capsys.readouterr().out


def test_daily_main_returns_distinct_code_when_target_lock_is_held(
        monkeypatch, tmp_path):
    state_path = tmp_path / "state" / "daily.json"
    lock_dir = state_path.parent / "locks"
    target_key = "\0".join((str(state_path.resolve()), "default-token"))
    monkeypatch.setattr(
        daily_triage, "get_gmail_service",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not contact Gmail")),
    )
    with ExclusiveRunLock(lock_dir, target_key):
        result = daily_triage.main([
            "daily", "--state-path", str(state_path), "--dry-run",
        ])
    assert result == LOCKED_EXIT_CODE
