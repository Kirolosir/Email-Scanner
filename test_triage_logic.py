"""Offline triage tests. All classification and Gmail services are fake."""
from types import SimpleNamespace
from types import MappingProxyType

import pytest

from account_profile import AccountProfile
from gmail_common import QuotaThrottle
from gmail_labeler import LabelDecision
from triage import (
    TemplateApprovals,
    execute_plan,
    fetch_messages,
    load_label_config,
    load_templates,
    plan_message,
    resolve_template,
)


def _approve(*keys):
    """Approve template keys by name for tests that exercise drafting."""
    return TemplateApprovals(name_only=set(keys))


def _email(**overrides):
    value = {
        "message_id": "m1", "from": "recruit@example.test",
        "subject": "Introduction", "body": "Seeded offline body",
        "thread_id": "t1", "rfc_message_id": "<m1@mail>",
        "label_names": [],
    }
    value.update(overrides)
    return value


def test_year_specific_templates_are_distinct_and_preferred(tmp_path):
    (tmp_path / "recruit_intro.txt").write_text("generic")
    (tmp_path / "recruit_intro_2027.txt").write_text("reply 2027")
    (tmp_path / "recruit_intro_2028.txt").write_text("reply 2028")
    templates = load_templates(tmp_path)

    p27 = plan_message(
        _email(body="I am in the Class of 2027."),
        templates, {}, {}, True, templates_dir=tmp_path,
        classifier=lambda _: {"category": "recruit_intro", "grad_year": "2027"},
        template_approvals=_approve("recruit_intro_2027", "recruit_intro_2028"),
    )
    p28 = plan_message(
        _email(body="I am a 2028 recruit."),
        templates, {}, {}, True, templates_dir=tmp_path,
        classifier=lambda _: {"category": "recruit_intro", "grad_year": "2028"},
        template_approvals=_approve("recruit_intro_2027", "recruit_intro_2028"),
    )

    assert p27["template"] == "reply 2027"
    assert p27["template_key"] == "recruit_intro_2027"
    assert p28["template"] == "reply 2028"
    assert p28["template_key"] == "recruit_intro_2028"


def test_template_falls_back_to_real_category_file(tmp_path):
    (tmp_path / "parent.txt").write_text("reviewed parent response")
    templates = load_templates(tmp_path)
    body, key, reason = resolve_template(
        templates, "parent", "2027", tmp_path, approvals=_approve("parent")
    )
    assert (body, key, reason) == ("reviewed parent response", "parent", None)


def test_placeholder_template_is_blocked_with_exact_requirement(tmp_path):
    path = tmp_path / "recruit_intro.txt"
    path.write_text("[PLACEHOLDER TEMPLATE - recruit_intro]\nunsafe")
    templates = load_templates(tmp_path)

    plan = plan_message(
        _email(body="Class of 2027 recruit introduction."),
        templates, {}, {}, True, templates_dir=tmp_path,
        classifier=lambda _: {"category": "recruit_intro", "grad_year": "2027"},
    )

    assert plan["template"] is None
    assert str(tmp_path / "recruit_intro_2027.txt") in plan["draft_skip"]
    assert str(path) in plan["draft_skip"]
    assert "placeholder unsafe" in plan["draft_skip"]


@pytest.mark.parametrize("result", [
    {"category": "unknown", "grad_year": "2027"},
    {"category": "invented", "grad_year": "2027"},
    {"category": "recruit_intro", "grad_year": "2099"},
])
def test_unknown_or_unsupported_cases_do_not_draft(result):
    plan = plan_message(
        _email(), {"recruit_intro": "reviewed"}, {}, {}, True,
        classifier=lambda _: result,
        template_approvals=_approve("recruit_intro"),
    )
    if result["category"] in {"unknown", "invented"}:
        assert plan["template"] is None
    else:
        # Structurally unsupported year safely falls back to a reviewed generic.
        assert plan["grad_year"] == "unknown"
        assert plan["template"] == "reviewed"


def test_classification_failure_isolated_and_not_drafted():
    def fail(_):
        raise TimeoutError("seeded failure")

    plan = plan_message(
        _email(), {"recruit_intro": "reviewed"}, {}, {}, True,
        classifier=fail,
    )
    assert plan["category"] == "unknown"
    assert plan["template"] is None
    assert plan["classification_error"] == "TimeoutError"


def test_conflict_blocks_draft_even_with_real_template():
    plan = plan_message(
        _email(label_names=["CAT-Parent"]),
        {"camp_inquiry": "reviewed"}, {},
        {"parent": "CAT-Parent", "camp_inquiry": "CAT-Camp"}, False,
        classifier=lambda _: {"category": "camp_inquiry", "grad_year": "unknown"},
    )
    assert plan["decision"].conflicts
    assert plan["template"] is None
    assert "manual review" in plan["draft_skip"]


class _Call:
    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def execute(self):
        if self.error:
            raise self.error
        return self.result


class _TriageFake:
    def __init__(self):
        self.modified = []
        self.drafted = []

    def users(self): return self
    def messages(self): return self
    def drafts(self): return self

    def get(self, userId, id, format=None):
        if id == "bad":
            return _Call(error=ConnectionError("offline fake"))
        return _Call(result={"id": id})

    def modify(self, userId, id, body):
        self.modified.append((id, body))
        return _Call(error=ConnectionError("label fake failure"))

    def create(self, userId, body):
        self.drafted.append(body)
        return _Call(result={"id": "d1"})


class _Log:
    def __init__(self): self.ids = []
    def record(self, value): self.ids.append(value)


def test_fetch_and_write_failures_are_isolated():
    service = _TriageFake()
    messages, failures = fetch_messages(
        service, ["good", "bad", "good2"], QuotaThrottle(100_000)
    )
    assert [m["id"] for m in messages] == ["good", "good2"]
    assert failures == [("bad", "ConnectionError")]

    plan = {
        "email": _email(), "decision": LabelDecision(add=["Real Label"]),
        "template": "reviewed reply",
    }
    log = _Log()
    labels, drafted, errors = execute_plan(
        service, plan, {"Real Label": "L1"}, QuotaThrottle(100_000), log
    )
    assert labels == []
    assert drafted is True, "a label failure must not suppress the safe draft"
    assert len(errors) == 1 and errors[0].startswith("label failed")
    assert log.ids == ["d1"]


def test_label_config_validation(tmp_path):
    assert load_label_config(None) == ({}, {})
    path = tmp_path / "labels.json"
    path.write_text('{"years":{"2027":"Exact Existing"},"categories":{}}')
    assert load_label_config(path) == ({"2027": "Exact Existing"}, {})
    path.write_text('{"years":[],"categories":{}}')
    with pytest.raises(ValueError):
        load_label_config(path)


def test_dynamic_account_evidence_gate_applies_its_configured_year_label():
    profile = AccountProfile(
        account="owner@example.test",
        categories=frozenset({"prospect"}),
        category_sender_types=MappingProxyType({"prospect": "recruit"}),
        year_labels=MappingProxyType({"2031": "Prospects/2031"}),
        category_labels=MappingProxyType({"prospect": "Triage/Prospect"}),
        supported_years=frozenset({"2031"}),
        evidence_categories=frozenset({"prospect"}),
        evidence_sender_types=frozenset({"recruit"}),
        evidence_rules=({
            "label": "Prospects/2031",
            "expected_value": "2031",
            "require_sender_type": frozenset({"recruit"}),
            "require_categories": frozenset({"prospect"}),
            "min_confidence": "high",
        },),
    )
    plan = plan_message(
        _email(body="I am a Class of 2031 prospective student-athlete."),
        {}, {"2031": "Prospects/2031"},
        {"prospect": "Triage/Prospect"}, False,
        classifier=lambda _: {
            "category": "prospect", "grad_year": "2031",
            "sender_type": "recruit", "confidence": "high",
        },
        profile=profile,
    )

    assert plan["classification"]["local_grad_year"] == "2031"
    assert plan["decision"].add == ["Triage/Prospect", "Prospects/2031"]


# --------------------------------------------------------------------
# --limit must bound the Gmail read, not only the post-fetch count.
#
# A live --limit 15 dry run spent 17 minutes downloading the full body of
# every message in a two-month window (5,770 messages) before discarding all
# but fifteen. The candidate loop stopped at the limit; the fetch did not.
# That is both a long read and an unnecessary retrieval of thousands of
# messages' contents.
# --------------------------------------------------------------------

class _CountingGmail:
    """Records how many full-message fetches actually happen."""

    def __init__(self, ids, processed_ids=()):
        self.ids = ids
        self.processed_ids = set(processed_ids)
        self.fetched = []

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id, format=None, metadataHeaders=None):
        self.fetched.append(id)
        label_ids = ["Label_Processed"] if id in self.processed_ids else []
        return _CountingCall({
            "id": id, "threadId": f"t{id}", "labelIds": label_ids,
            "payload": {"mimeType": "text/plain",
                        "headers": [{"name": "Subject", "value": "s"},
                                    {"name": "From", "value": "a@b.test"}],
                        "body": {"data": ""}},
        })


class _CountingCall:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


def test_fetch_messages_stops_fetching_once_the_limit_is_reached():
    from gmail_common import QuotaThrottle
    from triage import fetch_messages

    ids = [f"m{i}" for i in range(500)]
    service = _CountingGmail(ids)

    messages, failures = fetch_messages(
        service, ids, QuotaThrottle(units_per_second=10**6), limit=15
    )

    assert failures == []
    assert len(service.fetched) == 15, (
        f"fetched {len(service.fetched)} messages for a limit of 15; the "
        "Gmail read is not bounded by --limit"
    )
    assert len(messages) == 15


def test_fetch_without_a_limit_still_fetches_everything():
    """Control: the bound must be opt-in, not a silent truncation."""
    from gmail_common import QuotaThrottle
    from triage import fetch_messages

    ids = [f"m{i}" for i in range(25)]
    service = _CountingGmail(ids)
    fetch_messages(service, ids, QuotaThrottle(units_per_second=10**6))

    assert len(service.fetched) == 25


def test_large_fetch_can_use_multiple_services_and_preserves_order():
    ids = [f"m{i}" for i in range(25)]
    services = [_CountingGmail(ids), _CountingGmail(ids)]

    messages, failures = fetch_messages(
        services[0], ids, QuotaThrottle(units_per_second=10**6),
        services=services,
    )

    assert failures == []
    assert [message["id"] for message in messages] == ids
    assert sum(len(service.fetched) for service in services) == len(ids)


def test_skipped_messages_do_not_consume_the_fetch_budget():
    """Already-processed messages must not count toward the limit, or a run
    could stop before finding any real work."""
    from gmail_common import QuotaThrottle
    from triage import fetch_messages

    ids = [f"m{i}" for i in range(60)]
    already_done = {f"m{i}" for i in range(0, 40)}
    service = _CountingGmail(ids, processed_ids=already_done)

    def is_candidate(message):
        return message["id"] not in already_done

    fetch_messages(service, ids, QuotaThrottle(units_per_second=10**6),
                   limit=5, is_candidate=is_candidate)

    # 40 skipped + 5 real candidates = 45 fetched, then it stops.
    assert len(service.fetched) == 45, len(service.fetched)


def test_daily_triage_passes_limit_into_the_gmail_fetch():
    """The recurring failure in this codebase is a correct check whose call
    site never supplies the real value. fetch_messages growing a limit
    parameter is useless if daily_triage keeps calling it without one."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "fetch_messages"
    ]
    assert calls, "daily_triage.py no longer calls fetch_messages"

    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        assert "limit" in keywords, (
            f"daily_triage.py:{call.lineno} calls fetch_messages without a "
            "limit; the Gmail read would be unbounded again"
        )
        assert not isinstance(keywords["limit"], ast.Constant), (
            f"daily_triage.py:{call.lineno} passes a literal limit instead of "
            "the runtime --limit value"
        )
