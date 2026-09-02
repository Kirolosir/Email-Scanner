"""Deterministic offline demonstration of setup, policy, drafts, and restart.

No OAuth, Gmail, Gemini, secret, or network access occurs. All messages,
classifications, labels, and draft IDs exist only inside this process.
"""
import argparse
import tempfile
from pathlib import Path

from triage import TemplateApprovals
from daily_triage import DailyState, add_daily_review_policy, execute_daily_plan
from gmail_common import QuotaThrottle
from gmail_labeler import build_label_index
from setup_labels import apply_label_setup, plan_label_setup
from triage import plan_message
from triage_config import load_triage_label_config


class _Call:
    def __init__(self, result):
        self.result = result

    def execute(self):
        return self.result


class _FakeGmail:
    def __init__(self):
        self.resource = None
        self.labels_by_name = {"YEAR_LABEL": "Label_YEAR_LABEL"}
        self.modify_calls = []
        self.draft_calls = []

    def users(self): return self

    def labels(self):
        self.resource = "labels"
        return self

    def messages(self):
        self.resource = "messages"
        return self

    def drafts(self):
        self.resource = "drafts"
        return self

    def create(self, userId, body):
        if self.resource == "labels":
            label_id = f"Label_{len(self.labels_by_name) + 1}"
            self.labels_by_name[body["name"]] = label_id
            return _Call({"id": label_id, **body})
        draft_id = f"draft-{len(self.draft_calls) + 1}"
        self.draft_calls.append(body)
        return _Call({"id": draft_id})

    def modify(self, userId, id, body):
        self.modify_calls.append((id, body))
        return _Call({"id": id})


class _DraftLog:
    def __init__(self):
        self.ids = []

    def record(self, draft_id):
        self.ids.append(draft_id)


def _email(number, sender, body="OFFLINE SEEDED BODY"):
    return {
        "message_id": f"message-{number}",
        "from": sender,
        "subject": f"OFFLINE SEEDED SUBJECT {number}",
        "body": body,
        "thread_id": f"thread-{number}",
        "rfc_message_id": f"<offline-{number}@example.test>",
        "label_names": [],
    }


def run_demo():
    config = load_triage_label_config("label-config.example.json")
    service = _FakeGmail()
    setup_plan = plan_label_setup(service.labels_by_name, config)
    created, failures = apply_label_setup(service, config, setup_plan)
    assert not failures
    assert len(created) == len(config.creatable_names)

    years, categories = build_label_index(
        service.labels_by_name, config.years, config.categories
    )
    seeded = [
        (_email(1, "recruit@example.test", "I am in the Class of 2027."), {
            "category": "recruit_intro", "grad_year": "2027",
            "sender_type": "recruit", "confidence": "high",
            "evidence": "class of 2027", "reason": "offline", "valid": True,
        }),
        (_email(2, "parent@example.test"), {
            "category": "parent", "grad_year": "2027",
            "sender_type": "parent", "confidence": "high",
            "evidence": "mentions child", "reason": "offline", "valid": True,
        }),
        (_email(3, "ambiguous@example.test"), {
            "category": "unknown", "grad_year": "unknown",
            "sender_type": "unknown", "confidence": "low", "evidence": "",
            "reason": "offline", "valid": False,
        }),
    ]
    templates = {"recruit_intro_2027": "OFFLINE APPROVED TEST REPLY"}
    plans = []
    for email, result in seeded:
        plan = plan_message(
            email, templates, years, categories, False,
            classifier=lambda _email, result=result: result,
            # Synthetic offline template, explicitly approved for the demo.
            template_approvals=TemplateApprovals(name_only=set(templates)),
        )
        add_daily_review_policy(plan, config)
        plan["processed_label"] = config.system["processed"]
        plans.append(plan)

    with tempfile.TemporaryDirectory() as directory:
        state_path = Path(directory) / "state" / "daily.json"
        state = DailyState(state_path)
        log = _DraftLog()
        throttle = QuotaThrottle(100_000)
        draft_threads = {}
        for plan in plans:
            _labels, _draft_id, errors = execute_daily_plan(
                service, plan, service.labels_by_name, throttle, log,
                state, draft_threads,
            )
            assert errors == []

        first_draft_count = len(service.draft_calls)
        restarted = DailyState(state_path).load()
        for plan in plans:
            _labels, _draft_id, errors = execute_daily_plan(
                service, plan, service.labels_by_name, throttle, log,
                restarted, draft_threads,
            )
            assert errors == []
        assert len(service.draft_calls) == first_draft_count == 1
        assert log.ids == ["draft-1"]

    recruit_labels = set(plans[0]["decision"].add)
    parent_labels = set(plans[1]["decision"].add)
    assert "YEAR_LABEL" in recruit_labels
    assert "YEAR_LABEL" not in parent_labels
    assert config.system["needs_review"] in parent_labels
    assert config.system["needs_review"] in plans[2]["decision"].add

    print("Offline daily-triage demonstration passed:")
    print(f"  configured labels created: {len(created)}")
    print("  actual 2027 recruit received YEAR_LABEL")
    print("  parent mentioning 2027 did not receive YEAR_LABEL")
    print("  missing/unknown replies routed to Needs Review")
    print("  one synthetic draft created; restart created zero duplicates")
    print("  Gmail, Gemini, OAuth, and network calls: 0")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the deterministic fake-Gmail daily triage demonstration."
    )
    parser.parse_args(argv)
    run_demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
