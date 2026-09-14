"""Offline daily-triage tests using only fake Gmail and stub classifiers."""
import ast
import datetime as dt
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from daily_triage import (
    DailyState,
    add_daily_review_policy,
    already_processed_for_draft_policy,
    build_daily_query,
    build_history_query,
    build_initial_query,
    candidate_read_limit,
    execute_daily_plan,
    list_existing_draft_threads,
    reconcile_existing_drafts,
    validate_message_id_override,
)
import daily_triage
from gmail_common import QuotaThrottle, list_message_ids_by_query
from gmail_labeler import LabelDecision
from triage import plan_message
from triage_config import TriageLabelConfig
from private_runtime import ExclusiveRunLock, LOCKED_EXIT_CODE


CONFIG = TriageLabelConfig(
    years={"2027": "YEAR_LABEL"},
    categories={
        "recruit_intro": "Intro",
        "parent": "Parent",
        "other_coach": "Coach",
        "other": "Other",
    },
    system={"needs_review": "Needs Review", "processed": "Processed"},
)
ACCOUNT_LABELS = {
    "YEAR_LABEL": "Y27", "Intro": "C1", "Parent": "C2", "Coach": "C3",
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
def test_queries_include_archived_received_mail_and_exclude_unsafe_mailboxes(
    builder, value, fragment,
):
    query = builder(value)
    assert fragment in query
    assert "in:inbox" not in query
    for clause in ("-in:spam", "-in:trash", "-in:sent", "-in:drafts"):
        assert clause in query


def test_history_query_has_no_age_cutoff_but_keeps_mailbox_exclusions():
    query = build_history_query()
    assert "newer_than:" not in query
    assert "in:inbox" not in query
    for clause in ("-in:spam", "-in:trash", "-in:sent", "-in:drafts"):
        assert clause in query


def test_private_message_id_override_is_strict_and_bounded():
    assert validate_message_id_override(["m1", "m2"], 2) == ["m1", "m2"]
    for values, limit in ((["m1", "m2"], 1), (["m1", "m1"], 2),
                          (["bad id"], 1), ("m1", 1)):
        with pytest.raises(ValueError):
            validate_message_id_override(values, limit)


def test_only_actual_recruit_gets_the_year_label():
    templates = {
        "recruit_intro_2027": "approved recruit reply",
        "parent": "approved parent reply",
        "other_coach": "approved coach reply",
    }
    cases = [
        ("recruit_intro", "recruit", {"Intro", "YEAR_LABEL"}),
        ("parent", "parent", {"Parent"}),
        ("other_coach", "coach", {"Coach"}),
    ]
    for category, sender_type, expected in cases:
        plan = plan_message(
            _email(), templates, CONFIG.years, CONFIG.categories, False,
            classifier=lambda _email, c=category, s=sender_type: _classification(c, s),
        )
        assert set(plan["decision"].add) == expected


def _automated_plan():
    """A plan shaped exactly as plan_message leaves suppressed automated mail."""
    return {
        "email": {"message_id": "m1", "label_names": []},
        "category": "unknown",
        "sender_type": "unknown",
        "classification": {"valid": True},
        "classification_error": None,
        "decision": LabelDecision(add=[]),
        "draft_skip": "bounce or unsafe automated return path; not drafting",
        "suppression_code": "automated_message",
    }


def test_automated_mail_is_filed_without_review_for_a_per_category_account():
    """Newsletters and bounces must not flood Needs Review on an account
    that never enabled account-wide drafting."""
    plan = add_daily_review_policy(_automated_plan(), CONFIG)

    assert plan["needs_review"] is False
    assert plan["review_reasons"] == []
    assert "Needs Review" not in plan["decision"].add


def test_automated_mail_is_surfaced_for_review_under_account_wide_drafting():
    """With drafting approved for every replyable message, a message the run
    refused to draft is a decision the owner should see, not file silently."""
    profile = SimpleNamespace(draft_all_replyable_messages=True)
    plan = add_daily_review_policy(_automated_plan(), CONFIG, profile)

    assert plan["needs_review"] is True
    assert "Needs Review" in plan["decision"].add
    assert any("automated return path" in reason
               for reason in plan["review_reasons"])


def test_runtime_passes_the_real_profile_to_the_daily_review_policy():
    """A hardcoded or omitted profile would silently pick one policy for
    every account."""
    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "add_daily_review_policy"
    ]
    assert len(calls) == 1
    assert len(calls[0].args) == 3, "the review policy is not given a profile"
    assert "profile" in ast.unparse(calls[0].args[2])


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
        "decision": LabelDecision(add=["Intro", "YEAR_LABEL"]),
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


def test_messages_in_one_conversation_share_the_new_run_owned_draft(tmp_path):
    service = _ExecutionGmail()
    state = DailyState(tmp_path / "state.json")
    log = _Log()
    draft_threads = {}
    created_threads = set()
    first = _execution_plan()
    second = _execution_plan()
    second["email"] = _email(message_id="m2", thread_id="t1")

    for plan in (first, second):
        _added, draft_id, errors = execute_daily_plan(
            service, plan, ACCOUNT_LABELS, QuotaThrottle(100_000), log,
            state, draft_threads, created_threads,
        )
        assert errors == []
        assert draft_id == "draft-1"

    assert len(service.create_calls) == 1
    assert log.ids == ["draft-1"]
    assert state.record_for("m1")["status"] == "complete"
    assert state.record_for("m2")["status"] == "complete"


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
        "--max-scan", "25", "--limit", "25", "--max-drafts", "5",
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
        "--max-scan", "25", "--limit", "25", "--max-drafts", "5",
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


# --------------------------------------------------------------------
# --limit must count classifiable messages, not raw fetches.
#
# A live --limit 15 dry run in a mailbox that is ~88% bulk spent fourteen of
# its fifteen slots on automated mail that was suppressed immediately after
# being fetched, producing exactly one draft. The budget and the suppression
# rule have to agree, or the limit measures the wrong thing.
# --------------------------------------------------------------------

def _message(message_id, *, bulk=False, processed=False):
    headers = [{"name": "Subject", "value": f"subject {message_id}"},
               {"name": "From", "value": "person@example.test"}]
    if bulk:
        headers.append({"name": "List-Unsubscribe",
                        "value": "<mailto:u@example.test>"})
    return {
        "id": message_id, "threadId": f"t{message_id}",
        "labelIds": ["Label_Processed"] if processed else [],
        "payload": {"mimeType": "text/plain", "headers": headers,
                    "body": {"data": ""}},
    }


class _LimitGmail:
    def __init__(self, messages):
        self._messages = {m["id"]: m for m in messages}
        self.fetched = []

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id, format=None, metadataHeaders=None):
        self.fetched.append(id)
        return _LimitCall(self._messages[id])


class _LimitCall:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result
# --------------------------------------------------------------------
# A dry run must show the wording it would create.
#
# The whole purpose of a dry run is deciding whether to authorize real
# drafts. A "Draft: yes" column cannot support that decision - the first
# live dry run reported one draft without ever showing what it said.
# --------------------------------------------------------------------

def _plan_with_draft(subject, category, body, source="ai"):
    return {
        "category": category,
        "template": body,
        "draft_source": source,
        "email": {"subject": subject, "from": "someone@example.test",
                  "reply_address": "someone@example.test"},
    }


def test_preview_shows_the_full_generated_wording():
    from daily_triage import render_draft_preview

    body = ("LEGACY GENERATED WARNING\n\n"
            "Thanks for reaching out. I will take a look and follow up.")
    text = render_draft_preview([_plan_with_draft("A job for you",
                                                  "job_opportunities", body)])

    assert "Thanks for reaching out" in text
    assert "LEGACY GENERATED WARNING" in text
    assert "job_opportunities" in text
    assert "A job for you" in text


def test_preview_shows_every_draft_not_only_the_first():
    from daily_triage import render_draft_preview

    plans = [
        _plan_with_draft("s1", "job_opportunities", "first body text"),
        _plan_with_draft("s2", "shopping_and_discounts", "second body text"),
        _plan_with_draft("s3", "financial_services", "third body text"),
    ]
    text = render_draft_preview(plans)

    for fragment in ("first body text", "second body text", "third body text"):
        assert fragment in text
    assert "all 3 draft(s)" in text


def test_preview_omits_plans_that_would_not_draft():
    from daily_triage import render_draft_preview

    plans = [
        _plan_with_draft("drafted", "job_opportunities", "real body"),
        {"category": "sports_recruiting", "template": None,
         "draft_source": None, "email": {"subject": "not drafted"}},
    ]
    text = render_draft_preview(plans)

    assert "real body" in text
    assert "not drafted" not in text
    assert "all 1 draft(s)" in text


def test_preview_is_empty_when_nothing_would_draft():
    from daily_triage import render_draft_preview

    plans = [{"category": "x", "template": None, "email": {"subject": "s"}}]
    assert render_draft_preview(plans) == ""


def test_preview_is_suppressed_in_scheduled_runs():
    """Unattended output must stay free of subjects and message-derived
    text; the preview is an interactive review aid only."""
    from daily_triage import render_draft_preview

    plans = [_plan_with_draft("private subject", "job_opportunities",
                              "private body")]
    text = render_draft_preview(plans, scheduled=True)

    assert text == ""
    assert "private subject" not in text
    assert "private body" not in text


def test_dry_run_actually_calls_the_preview():
    """Wiring: rendering exists but is useless if the run never prints it."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "render_draft_preview"
    ]
    assert calls, (
        "daily_triage never calls render_draft_preview; a dry run would "
        "again report drafts without showing their wording"
    )
    for call in calls:
        keywords = {kw.arg for kw in call.keywords}
        assert "scheduled" in keywords, (
            "the preview call must pass the scheduled flag, or unattended "
            "runs would print message-derived text"
        )


def test_saving_state_makes_every_new_parent_private(tmp_path):
    """A nested state_dir must not leave a world-listable parent.

    The live account uses triage-state/<account>. mkdir's mode covers only
    the leaf, so the real run created triage-state at 0755, publishing which
    accounts are being triaged to any local user.
    """
    import os
    import stat
    from daily_triage import DailyState

    state = DailyState(tmp_path / "triage-state" / "someone" / "daily.json")
    state.save()

    for path in (tmp_path / "triage-state",
                 tmp_path / "triage-state" / "someone"):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700, f"{path} is mode {mode:03o}, expected 700"
# --------------------------------------------------------------------
# End to end: a real run that drafts nothing must leave draft-logs/ clean.
# --------------------------------------------------------------------

def test_apply_run_with_no_drafts_writes_no_draft_log(
        monkeypatch, tmp_path, capsys):
    """The live case that motivated this: drafting off for every category,
    so the run labels normally and creates no drafts. Before, each such run
    dropped a header-only file into draft-logs/."""
    import campaign

    service = _MainFakeGmail()
    monkeypatch.setattr(daily_triage, "get_gmail_service",
                        lambda **_kwargs: service)
    log_dir = tmp_path / "draft-logs"
    monkeypatch.setattr(campaign, "DRAFT_LOG_DIR", str(log_dir))
    templates = tmp_path / "templates"
    templates.mkdir()

    result = daily_triage.main([
        "initial", "--state-path", str(tmp_path / "state" / "daily.json"),
        "--templates", str(templates), "--apply", "--yes",
    ], classifier=_high_recruit)

    assert result == 0
    assert service.create_calls == [], "no draft should have been created"
    written = sorted(p.name for p in log_dir.glob("*.log")) if \
        log_dir.exists() else []
    assert written == [], f"zero-draft run left log files: {written}"
    assert "Draft-id log:" not in capsys.readouterr().out


# --------------------------------------------------------------------
# --limit N is a budget of Gmail WRITES: label adds plus drafts, N total.
#
# It used to bound classification only. A measured --limit 15 run wrote up
# to 182 labels across 158 messages, so the flag an operator reaches for to
# keep a pilot small did not bound what the pilot changed.
# --------------------------------------------------------------------

def _plan(labels, draft=False, needs_review=False):
    from gmail_labeler import LabelDecision

    return {
        "decision": LabelDecision(add=list(labels)),
        "template": "body" if draft else None,
        "needs_review": needs_review,
        "email": {"subject": "s", "message_id": "m", "thread_id": "t"},
        "processed_label": "Processed",
    }


def _total_writes(plans):
    from daily_triage import plan_write_cost

    return sum(plan_write_cost(p) for p in plans)


def test_write_cost_counts_labels_the_processed_label_and_the_draft():
    from daily_triage import plan_write_cost

    assert plan_write_cost(_plan([])) == 1                   # processed only
    assert plan_write_cost(_plan(["A"])) == 2                # + one label
    assert plan_write_cost(_plan(["A", "B"])) == 3
    assert plan_write_cost(_plan(["A"], draft=True)) == 3     # + the draft


def test_a_limited_run_never_exceeds_n_total_writes():
    """The guarantee: label adds plus drafts, combined, stay within --limit."""
    from daily_triage import plans_within_write_budget

    plans = [_plan(["Cat", "Review"], draft=True) for _ in range(20)]  # 4 each

    for limit in range(1, 30):
        admitted, deferred = plans_within_write_budget(plans, limit)
        writes = _total_writes(admitted)
        assert writes <= limit, (
            f"--limit {limit} admitted {writes} writes across "
            f"{len(admitted)} plan(s)"
        )
        assert len(admitted) + len(deferred) == len(plans)


def test_the_bound_holds_for_mixed_plan_shapes():
    from daily_triage import plans_within_write_budget

    plans = [
        _plan([]),                          # 1 write
        _plan(["A"]),                       # 2
        _plan(["A", "B"], draft=True),      # 4
        _plan(["A"], draft=True),           # 3
        _plan(["A", "B", "C"]),             # 4
    ]
    for limit in range(1, 20):
        admitted, _ = plans_within_write_budget(plans, limit)
        assert _total_writes(admitted) <= limit


def test_admission_is_by_whole_plan_never_a_partial_message():
    """Stopping mid-plan would label a message without marking it processed,
    so the next run would see it as new work."""
    from daily_triage import plans_within_write_budget

    plans = [_plan(["A", "B"], draft=True)] * 3          # 4 writes each
    admitted, deferred = plans_within_write_budget(plans, 7)

    assert len(admitted) == 1, "a second plan was partially admitted"
    assert _total_writes(admitted) == 4
    assert len(deferred) == 2


def test_a_limit_too_small_for_any_plan_admits_nothing():
    from daily_triage import plans_within_write_budget

    admitted, deferred = plans_within_write_budget(
        [_plan(["A", "B"], draft=True)], 2
    )
    assert admitted == []
    assert len(deferred) == 1


def test_no_limit_admits_every_plan():
    from daily_triage import plans_within_write_budget

    plans = [_plan(["A"], draft=True) for _ in range(5)]
    admitted, deferred = plans_within_write_budget(plans, None)
    assert len(admitted) == 5 and deferred == []


def test_selection_caps_candidates_because_each_costs_a_write():
    """Every touched message costs at least the processed label, so more
    than `limit` candidates can never be afforded."""
    from daily_triage import select_candidates

    messages = [{"id": f"m{n}"} for n in range(50)]
    candidates, skipped = select_candidates(
        messages, 5, already_processed=lambda m: False
    )
    assert len(candidates) == 5
    assert skipped == 0


def test_selection_still_skips_already_processed_messages():
    from daily_triage import select_candidates

    messages = [{"id": f"done{n}"} for n in range(4)]
    messages += [{"id": f"new{n}"} for n in range(3)]
    candidates, skipped = select_candidates(
        messages, 3,
        already_processed=lambda m: m["id"].startswith("done"),
    )
    assert skipped == 4
    assert [m["id"] for m in candidates] == ["new0", "new1", "new2"]


def test_account_wide_policy_revisits_old_label_only_completion_once(tmp_path):
    state = DailyState(tmp_path / "state.json")
    state.data["messages"]["old"] = {
        "status": "complete", "thread_id": "t1", "draft_id": "",
    }
    message = {"id": "old", "_label_names": ["Processed"]}

    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=False
    ) is True
    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=True
    ) is False

    state.record_complete("old", "t1")
    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=True
    ) is True


def test_policy_upgrade_revisits_prior_no_draft_completion(tmp_path):
    state = DailyState(tmp_path / "state.json")
    state.data["messages"]["notification"] = {
        "status": "complete", "thread_id": "t1", "draft_id": "",
        "draft_policy_version": 2,
    }
    message = {
        "id": "notification", "threadId": "t1",
        "_label_names": ["Processed"],
    }

    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=True,
        draft_threads={},
    ) is False


def test_recorded_draft_is_complete_across_draft_policy_upgrade(tmp_path):
    state = DailyState(tmp_path / "state.json")
    state.data["messages"]["drafted"] = {
        "status": "complete", "thread_id": "t1", "draft_id": "d1",
    }
    assert already_processed_for_draft_policy(
        {"id": "drafted", "_label_names": ["Processed"]},
        "Processed", state, account_wide_drafting=True,
    ) is True


def test_recorded_draft_is_revisited_when_it_was_deleted_from_gmail(tmp_path):
    state = DailyState(tmp_path / "state.json")
    state.data["messages"]["drafted"] = {
        "status": "complete", "thread_id": "t1", "draft_id": "d1",
        "draft_policy_version": 2,
    }
    message = {
        "id": "drafted", "threadId": "t1", "_label_names": ["Processed"],
    }
    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=True,
        draft_threads={"t1": "d1"},
    ) is True
    assert already_processed_for_draft_policy(
        message, "Processed", state, account_wide_drafting=True,
        draft_threads={},
    ) is False


def test_missing_program_owned_draft_is_recreated(tmp_path):
    plan = _execution_plan()
    state = DailyState(tmp_path / "state.json")
    state.record_complete("m1", "t1", "deleted-draft", draft_policy_version=2)
    reconcile_existing_drafts([plan], state, {}, CONFIG)
    assert plan["replace_missing_owned_draft"] is True
    assert plan["template"] is not None

    service = _ExecutionGmail()
    log = _Log()
    _added, draft_id, errors = execute_daily_plan(
        service, plan, ACCOUNT_LABELS, QuotaThrottle(100_000), log,
        state, {}, set(),
    )
    assert errors == []
    assert draft_id == "draft-1"
    assert state.record_for("m1")["draft_id"] == "draft-1"


def test_account_wide_candidate_read_stops_at_draft_cap():
    assert candidate_read_limit(25, 5, account_wide_drafting=True) == 5
    assert candidate_read_limit(3, 5, account_wide_drafting=True) == 3
    assert candidate_read_limit(None, 5, account_wide_drafting=True) == 5
    assert candidate_read_limit(25, 0, account_wide_drafting=True) == 25
    assert candidate_read_limit(25, 5, account_wide_drafting=False) == 25


def test_the_run_applies_the_budget_before_previewing():
    """Wiring. If the executor applied the budget alone, every bounded dry
    run would overstate the writes an --apply run performs."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "plans_within_write_budget"
    ]
    assert calls, "daily_triage never applies the write budget"
    for call in calls:
        names = {a.id for a in call.args if isinstance(a, ast.Name)}
        assert "plans" in names, "the budget must be applied to the real plans"
        assert any(
            isinstance(a, ast.Attribute) and a.attr == "limit" for a in call.args
        ), "the budget must be given the real --limit, not a constant"


class _CountingGmail(_MainFakeGmail):
    """Multi-message fake that tallies real Gmail write operations."""

    def __init__(self, message_count=12):
        super().__init__()
        self._messages = []
        for n in range(message_count):
            copy = json.loads(json.dumps(self.message))
            copy["id"] = f"msg-{n}"
            copy["threadId"] = f"thread-{n}"
            self._messages.append(copy)
        self._by_id = {m["id"]: m for m in self._messages}

    def list(self, **kwargs):
        if self.resource == "messages":
            return _Call({"messages": [{"id": m["id"]} for m in self._messages]})
        return super().list(**kwargs)

    def get(self, **kwargs):
        message_id = kwargs.get("id")
        if self.resource == "messages" and message_id in self._by_id:
            return _Call(self._by_id[message_id])
        return super().get(**kwargs)

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return _Call({"id": f"d{len(self.create_calls)}"})

    @property
    def label_adds(self):
        return sum(len(c["body"].get("addLabelIds", [])) for c in self.modify_calls)

    @property
    def total_writes(self):
        return self.label_adds + len(self.create_calls)


def test_end_to_end_apply_run_never_writes_more_than_the_limit(
        monkeypatch, tmp_path):
    """The guarantee measured against real Gmail calls, not the planner.

    Counts every addLabelIds entry across every modify call, plus every
    draft create, and asserts the total stays within --limit.
    """
    import campaign

    for limit in (1, 2, 3, 5, 8):
        service = _CountingGmail(message_count=12)
        bound = service
        monkeypatch.setattr(daily_triage, "get_gmail_service",
                            lambda **_k: bound)
        monkeypatch.setattr(campaign, "DRAFT_LOG_DIR",
                            str(tmp_path / f"logs-{limit}"))
        templates = tmp_path / f"templates-{limit}"
        templates.mkdir()

        result = daily_triage.main([
            "initial",
            "--state-path", str(tmp_path / f"state-{limit}" / "daily.json"),
            "--templates", str(templates),
            "--limit", str(limit), "--apply", "--yes",
        ], classifier=_high_recruit)

        assert result == 0, f"--limit {limit} exited {result}"
        assert service.total_writes <= limit, (
            f"--limit {limit} performed {service.total_writes} writes "
            f"({service.label_adds} label adds + "
            f"{len(service.create_calls)} drafts)"
        )


def test_end_to_end_apply_run_never_creates_more_than_max_drafts(
        monkeypatch, tmp_path):
    """Measure the independent cap at the real drafts().create boundary."""
    import campaign

    service = _CountingGmail(message_count=8)
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_k: service)
    monkeypatch.setattr(campaign, "DRAFT_LOG_DIR", str(tmp_path / "logs"))
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "recruit_intro_2027.txt").write_text(
        "Reviewed offline reply", encoding="utf-8"
    )
    state_path = tmp_path / "state" / "daily.json"
    report_path = tmp_path / "review" / "pilot.json"

    result = daily_triage.main([
        "initial", "--state-path", str(state_path),
        "--templates", str(templates),
        "--templates-approved", "recruit_intro_2027",
        "--limit", "100", "--max-drafts", "2", "--apply", "--yes",
        "--review-report", str(report_path),
    ], classifier=_high_recruit)

    assert result == 0
    assert len(service.create_calls) == 2
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(saved["messages"]) == 2, (
        "draft-limited messages were partially labeled or marked processed"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["counts"]["deferred_draft_limit"] == 6
    assert sum(item["draft_created"] for item in report["messages"]) == 2
    assert len(report["messages"]) == 8
    report_text = report_path.read_text(encoding="utf-8")
    for private in (
        "PRIVATE SUBJECT MARKER", "private-sender@example.test",
        "PRIVATE BODY MARKER", "private-message-id", "thread-",
    ):
        assert private not in report_text


def test_dry_run_models_max_drafts_without_writing(monkeypatch, tmp_path, capsys):
    service = _CountingGmail(message_count=6)
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_k: service)
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "recruit_intro_2027.txt").write_text(
        "Reviewed offline reply", encoding="utf-8"
    )

    result = daily_triage.main([
        "initial", "--state-path", str(tmp_path / "state" / "daily.json"),
        "--templates", str(templates),
        "--templates-approved", "recruit_intro_2027",
        "--limit", "100", "--max-drafts", "1", "--dry-run",
    ], classifier=_high_recruit)

    assert result == 0
    assert service.create_calls == [] and service.modify_calls == []
    output = capsys.readouterr().out
    assert "Drafts:       up to 1" in output
    assert "candidate(s) deferred by --max-drafts" in output


def test_deferred_work_does_not_mark_the_day_complete(monkeypatch, tmp_path):
    """A budget-truncated daily run must not set the same-day guard, or the
    remainder would be hidden until tomorrow."""
    import campaign

    service = _CountingGmail(message_count=12)
    monkeypatch.setattr(daily_triage, "get_gmail_service",
                        lambda **_k: service)
    monkeypatch.setattr(campaign, "DRAFT_LOG_DIR", str(tmp_path / "logs"))
    templates = tmp_path / "templates"
    templates.mkdir()
    state_path = tmp_path / "state" / "daily.json"

    result = daily_triage.main([
        "daily", "--state-path", str(state_path),
        "--templates", str(templates),
        # 5 admits exactly one 4-write plan and defers the rest.
        "--limit", "5", "--apply", "--yes",
    ], classifier=_high_recruit)

    assert result == 0
    assert service.total_writes <= 5
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["messages"], "nothing was processed, so the test is vacuous"
    assert saved["last_daily_date"] is None, (
        "the day was marked complete while work was still deferred"
    )


def test_an_unlimited_daily_run_still_marks_the_day_complete(
        monkeypatch, tmp_path):
    """Control for the test above: without deferral the guard must still be
    set, or the same-day protection is simply gone."""
    import campaign

    service = _CountingGmail(message_count=2)
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_k: service)
    monkeypatch.setattr(campaign, "DRAFT_LOG_DIR", str(tmp_path / "logs2"))
    templates = tmp_path / "templates2"
    templates.mkdir()
    state_path = tmp_path / "state2" / "daily.json"

    result = daily_triage.main([
        "daily", "--state-path", str(state_path),
        "--templates", str(templates), "--apply", "--yes",
    ], classifier=_high_recruit)

    assert result == 0
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["last_daily_date"] is not None


def test_a_budget_that_admits_nothing_does_not_mark_the_day_complete(
        monkeypatch, tmp_path):
    """The all-deferred case takes the "nothing eligible" early return, which
    is a separate mark_daily_complete call site from the normal one. If it
    sets the guard, a limit too small to make progress silently burns the
    day: the remaining mail stays hidden until tomorrow, every day.

    No state is written when nothing is processed, so the journal is seeded
    first and checked for an unchanged last_daily_date.
    """
    import campaign

    service = _CountingGmail(message_count=6)
    monkeypatch.setattr(daily_triage, "get_gmail_service", lambda **_k: service)
    monkeypatch.setattr(campaign, "DRAFT_LOG_DIR", str(tmp_path / "logs"))
    templates = tmp_path / "templates"
    templates.mkdir()
    state_path = tmp_path / "state" / "daily.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps(
        {"version": 1, "last_daily_date": None, "messages": {}}
    ), encoding="utf-8")

    # Each plan here costs 4 writes, so a budget of 2 admits none of them.
    result = daily_triage.main([
        "daily", "--state-path", str(state_path),
        "--templates", str(templates),
        "--limit", "2", "--apply", "--yes",
    ], classifier=_high_recruit)

    assert result == 0
    assert service.total_writes == 0, "writes happened despite admitting nothing"
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["last_daily_date"] is None, (
        "a run that processed nothing marked the day complete, hiding the "
        "deferred work behind the same-day guard"
    )
