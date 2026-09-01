"""Offline-first end-to-end demo over eight seeded emails.

Gmail is always faked. Classification is stubbed by default, so the normal
command makes no network calls. A live Gemini call requires explicit consent:

    python demo_triage_flow.py           # offline, deterministic
    python demo_triage_flow.py --live    # real Gemini calls; fake Gmail

The fake account is seeded with only SOME of the placeholder labels, on
purpose: the missing ones prove the "don't create, just log" path. Two
messages arrive pre-labeled to exercise the never-overwrite and conflict
rules.
"""
import base64
import argparse
import email as email_mod
import os
import sys
import tempfile

from gmail_common import QuotaThrottle, build_draft_body
from gmail_labeler import build_label_index
from test_emails import TEST_EMAILS
from triage import (
    TemplateApprovals,
    attach_label_names,
    execute_plan,
    load_templates,
    message_to_email,
    plan_message,
)

# The fake account has year labels for 2027/2028 and only three of the
# five category labels - so recruit_update / other have no category label
# and must be logged as skips rather than created.
#
# 'Triage/Camp Inquiry' IS seeded specifically so the conflict path can
# fire on message 5: without it, decide_labels() short-circuits on "no
# matching label" and the conflict branch is never reached.
SEEDED_LABELS = {
    "INBOX": "Label_INBOX",
    "Recruits/2027": "Label_Y27",
    "Recruits/2028": "Label_Y28",
    "Triage/Recruit Intro": "Label_CI",
    "Triage/Parent": "Label_CP",
    "Triage/Camp Inquiry": "Label_CC",
}

# message index (0-based) -> label names already on it
PRE_LABELED = {
    # Already tagged 2027; classifier will say 2027 too. Must not double-apply.
    0: ["Recruits/2027"],
    # Tagged Parent, but the classifier will say camp_inquiry -> conflict.
    4: ["Triage/Parent"],
}

STUB_CLASSIFICATIONS = [
    {"category": "recruit_intro", "grad_year": "2027"},
    {"category": "recruit_intro", "grad_year": "2028"},
    {"category": "recruit_update", "grad_year": "unknown"},
    {"category": "parent", "grad_year": "unknown"},
    {"category": "camp_inquiry", "grad_year": "unknown"},
    {"category": "other", "grad_year": "unknown"},
    {"category": "other", "grad_year": "unknown"},
    {"category": "other", "grad_year": "unknown"},
]


class _FakeCall:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _FakeGmail:
    """Fake Gmail service holding the seeded messages, recording every
    modify() and drafts().create() so the test can assert on them."""

    def __init__(self, messages):
        self._messages = {m["id"]: m for m in messages}
        self.modify_calls = []
        self.created_drafts = []
        self._draft_seq = 0

    def users(self):
        return self

    def messages(self):
        return self

    def drafts(self):
        return self

    def labels(self):
        return self

    def list(self, userId, **kwargs):
        if "labelIds" in kwargs:
            return _FakeCall({"messages": [{"id": mid}
                                           for mid in self._messages]})
        return _FakeCall({"labels": [{"name": n, "id": i}
                                     for n, i in SEEDED_LABELS.items()]})

    def get(self, userId, id, format=None, metadataHeaders=None):
        return _FakeCall(self._messages[id])

    def modify(self, userId, id, body):
        self.modify_calls.append({"id": id, "body": body})
        # Reflect the change so re-reads would see it.
        self._messages[id].setdefault("labelIds", []).extend(
            body.get("addLabelIds", [])
        )
        return _FakeCall(self._messages[id])

    def create(self, userId, body):
        self._draft_seq += 1
        draft_id = f"draft-{self._draft_seq}"
        self.created_drafts.append({"id": draft_id, "body": body})
        return _FakeCall({"id": draft_id, "message": {"id": f"msg-{draft_id}"}})


def build_fake_messages():
    """Turn TEST_EMAILS into Gmail message resources, base64url-encoded
    the way the real API returns them."""
    messages = []
    for i, sample in enumerate(TEST_EMAILS):
        raw_body = base64.urlsafe_b64encode(
            sample["body"].encode("utf-8")
        ).decode().rstrip("=")

        label_ids = [SEEDED_LABELS["INBOX"]]
        for name in PRE_LABELED.get(i, []):
            label_ids.append(SEEDED_LABELS[name])

        messages.append({
            "id": f"m{i + 1}",
            "threadId": f"t{i + 1}",
            "internalDate": str(1_700_000_000_000 + i),
            "labelIds": label_ids,
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": sample["from"]},
                    {"name": "Subject", "value": sample["subject"]},
                    {"name": "Message-ID", "value": f"<msg{i + 1}@mail>"},
                ],
                "body": {"data": raw_body},
            },
        })
    return messages


class _StubLog:
    def __init__(self):
        self.ids = []
        self.count = 0

    def record(self, draft_id):
        self.ids.append(draft_id)
        self.count += 1


def run_flow(use_stub):
    messages = build_fake_messages()
    service = _FakeGmail(messages)
    throttle = QuotaThrottle(units_per_second=100_000)  # no sleeping

    account_labels = dict(SEEDED_LABELS)
    year_labels, category_labels = build_label_index(account_labels)

    with tempfile.TemporaryDirectory() as templates_dir:
        write_demo_templates(templates_dir)
        templates = load_templates(templates_dir)

        print(f"Templates loaded:  {', '.join(sorted(templates))}")
        print(f"Year labels:       {year_labels}")
        print(f"Category labels:   {category_labels}\n")

        attach_label_names(messages, account_labels)

        plans = []
        for i, message in enumerate(messages):
            email = message_to_email(message)
            email["message_id"] = message["id"]
            classifier = None
            if use_stub:
                result = STUB_CLASSIFICATIONS[i]
                classifier = lambda _email, result=result: result
            plan = plan_message(
                email, templates, year_labels, category_labels,
                no_label=False, templates_dir=templates_dir,
                classifier=classifier,
                # Synthetic demo templates, explicitly approved for this
                # offline run only. Real runs require a reviewed artifact.
                template_approvals=TemplateApprovals(name_only=set(templates)),
            )
            plans.append(plan)

        draft_log = _StubLog()
        for plan in plans:
            execute_plan(service, plan, account_labels, throttle, draft_log)

    return plans, service, draft_log


def write_demo_templates(directory):
    """Create unmistakably synthetic templates used only by fake Gmail."""
    bodies = {
        "recruit_intro_2027": "OFFLINE TEST REPLY FOR A 2027 INTRODUCTION.",
        "recruit_intro_2028": "OFFLINE TEST REPLY FOR A 2028 INTRODUCTION.",
        "recruit_update": "OFFLINE TEST REPLY FOR A RECRUIT UPDATE.",
        "parent": "OFFLINE TEST REPLY FOR A PARENT MESSAGE.",
        "camp_inquiry": "OFFLINE TEST REPLY FOR A CAMP INQUIRY.",
    }
    for key, body in bodies.items():
        with open(os.path.join(directory, f"{key}.txt"), "w", encoding="utf-8") as f:
            f.write(body)


def print_results(plans, service):
    header = (f"{'#':<3} | {'Subject':<34} | {'Category':<15} | {'Yr':<5} | "
              f"{'Labels applied':<26} | Draft")
    print(header)
    print("-" * len(header))
    for i, plan in enumerate(plans, start=1):
        labels = ", ".join(plan["decision"].add) or "-"
        drafted = "yes" if plan["template"] is not None else "no"
        print(f"{i:<3} | {plan['email']['subject'][:34]:<34} | "
              f"{plan['category']:<15} | {(plan['grad_year'] or '-'):<5} | "
              f"{labels[:26]:<26} | {drafted}")

    print("\nNotes:")
    for i, plan in enumerate(plans, start=1):
        for conflict in plan["decision"].conflicts:
            print(f"  [{i}] CONFLICT: {conflict}")
        for skip in plan["decision"].skips:
            print(f"  [{i}] skip: {skip}")
        if plan["draft_skip"]:
            print(f"  [{i}] {plan['draft_skip']}")


def check(label, actual, expected):
    ok = actual == expected
    print(f"[{'ok  ' if ok else 'FAIL'}] {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def assert_invariants(plans, service, draft_log):
    print("\n--- Invariants ---")
    passed = []

    # No label call may ever remove a label.
    no_removes = all("removeLabelIds" not in c["body"]
                     for c in service.modify_calls)
    passed.append(check("no modify call ever removes a label", no_removes, True))

    # Message 1 was already tagged Recruits/2027; it must not be re-applied.
    m1 = plans[0]
    passed.append(check("pre-labeled year not re-applied",
                        "Recruits/2027" in m1["decision"].add, False))

    # Every label applied must exist in the account.
    applied = {name for p in plans for name in p["decision"].add}
    passed.append(check("every applied label already exists in account",
                        applied <= set(SEEDED_LABELS), True))

    # Drafts must only exist where a template existed.
    drafted_have_resolved_key = all(
        p["template_key"] is not None for p in plans if p["template"] is not None
    )
    passed.append(check("drafts only for categories with templates",
                        drafted_have_resolved_key, True))

    # 'other' must never get a draft - no template on purpose.
    other_drafted = any(p["template"] is not None
                        for p in plans if p["category"] == "other")
    passed.append(check("'other' never drafted (vendor/press safety)",
                        other_drafted, False))

    # Draft count matches log count.
    passed.append(check("every created draft was logged",
                        len(service.created_drafts), draft_log.count))

    # Drafts must be threaded replies to the right sender.
    ok_threading = True
    for created in service.created_drafts:
        raw = base64.urlsafe_b64decode(created["body"]["message"]["raw"])
        parsed = email_mod.message_from_bytes(raw)
        if not parsed["Subject"].lower().startswith("re:"):
            ok_threading = False
        if not parsed["In-Reply-To"]:
            ok_threading = False
        if created["body"]["message"].get("threadId") is None:
            ok_threading = False
    passed.append(check("drafts are threaded replies (Re:, In-Reply-To, threadId)",
                        ok_threading, True))

    # No send call is even reachable on the fake - assert we never tried.
    passed.append(check("no send attempted",
                        hasattr(service, "send"), False))

    # Message 5 arrives tagged Triage/Parent but classifies as camp_inquiry.
    # That must be recorded as a conflict and left alone, not overwritten.
    m5 = plans[4]
    passed.append(check("conflicting category detected",
                        len(m5["decision"].conflicts), 1))
    passed.append(check("conflicting category not applied",
                        "Triage/Camp Inquiry" in m5["decision"].add, False))
    applied_to_m5 = [c for c in service.modify_calls if c["id"] == "m5"]
    passed.append(check("conflict left existing label untouched",
                        all("Label_CP" not in c["body"].get("addLabelIds", [])
                            for c in applied_to_m5), True))

    return all(passed)


def check_no_label_flag():
    """--no-label must suppress all labeling but still allow drafting."""
    print("\n--- --no-label ---")
    messages = build_fake_messages()
    account_labels = dict(SEEDED_LABELS)
    attach_label_names(messages, account_labels)
    templates = {"recruit_intro_2027": "OFFLINE TEST REPLY."}
    year_labels, category_labels = build_label_index(account_labels)

    email = message_to_email(messages[0])
    email["message_id"] = messages[0]["id"]

    service = _FakeGmail(messages)
    plan = plan_message(
        email, templates, year_labels, category_labels, no_label=True,
        classifier=lambda _email: STUB_CLASSIFICATIONS[0],
        template_approvals=TemplateApprovals(name_only=set(templates)),
    )
    draft_log = _StubLog()
    labels, drafted, errors = execute_plan(
        service, plan, account_labels, QuotaThrottle(units_per_second=100_000),
        draft_log
    )

    passed = []
    passed.append(check("no labels applied", labels, []))
    passed.append(check("no modify call issued", service.modify_calls, []))
    passed.append(check("draft still created", drafted, True))
    passed.append(check("no errors", errors, []))
    return all(passed)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the triage flow with fake Gmail and seeded emails."
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Use live Gemini classification (Gmail remains fake)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    use_stub = not args.live
    mode = "stubbed classifications" if use_stub else "live Gemini"
    print(f"=== Triage flow over {len(TEST_EMAILS)} seeded emails ({mode}) ===\n")

    plans, service, draft_log = run_flow(use_stub)
    print_results(plans, service)
    ok = assert_invariants(plans, service, draft_log)
    ok = check_no_label_flag() and ok

    print(f"\n{'ALL INVARIANTS HELD' if ok else 'SOME CHECKS FAILED'}")
    print(f"Labels applied: {len(service.modify_calls)} | "
          f"Drafts created: {len(service.created_drafts)}")
    sys.exit(0 if ok else 1)
