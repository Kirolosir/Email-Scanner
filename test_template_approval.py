"""Offline tests for the per-template approval gate.

The rule under test: a real (non-placeholder) template must NOT produce a
draft until a human has explicitly approved that specific template key.
Approval is per-key, so approving one category can never activate another.

These exist because an untested safety rule silently regressed earlier this
week: a conflict test passed while exercising nothing, because the case it
described short-circuited before reaching the branch it meant to check. Each
test here therefore asserts both halves - that the gate blocks when it should
AND that drafting still works once approved - so a gate that is accidentally
disabled fails loudly instead of passing vacuously.
"""
import json

import pytest

from triage import (
    TemplateApprovals,
    build_template_approvals,
    load_template_approval,
    precheck_template_approval,
    load_templates,
    plan_message,
    resolve_template,
    template_digest,
)

REAL_BODY = "Thanks for reaching out. Coach will follow up shortly."


def _email(**overrides):
    value = {
        "message_id": "m1", "from": "recruit@example.test",
        "subject": "Introduction", "body": "I am in the Class of 2027.",
        "thread_id": "t1", "rfc_message_id": "<m1@mail>",
        "label_names": [],
    }
    value.update(overrides)
    return value


def _plan(templates, approvals=None, category="recruit_intro", year="2027",
          templates_dir="templates"):
    return plan_message(
        _email(), templates, {}, {}, True, templates_dir=templates_dir,
        classifier=lambda _: {"category": category, "grad_year": year},
        template_approvals=approvals,
    )


# --------------------------------------------------------------------
# The core requirement: real content alone must never be enough.
# --------------------------------------------------------------------

def test_real_template_without_approval_creates_no_draft():
    """THE regression guard: real wording present, no approval -> no draft."""
    plan = _plan({"recruit_intro": REAL_BODY})

    assert plan["template"] is None, (
        "a real template produced a draft with no approval - the template "
        "approval gate is disabled"
    )
    assert plan["template_key"] is None
    assert "template unapproved" in plan["draft_skip"]


def test_real_template_with_matching_approval_does_create_a_draft():
    """The other half: the gate must not block approved wording, otherwise
    the test above could pass simply because drafting is broken."""
    plan = _plan(
        {"recruit_intro": REAL_BODY},
        approvals=TemplateApprovals(name_only={"recruit_intro"}),
    )

    assert plan["template"] == REAL_BODY
    assert plan["template_key"] == "recruit_intro"
    assert plan["draft_skip"] is None


def test_default_approvals_are_empty_and_fail_closed():
    """Omitting the argument entirely must not approve anything."""
    assert TemplateApprovals().approved_keys() == []
    body, key, reason = resolve_template(
        {"parent": REAL_BODY}, "parent", "unknown"
    )
    assert (body, key) == (None, None)
    assert "template unapproved" in reason


# --------------------------------------------------------------------
# Per-category isolation.
# --------------------------------------------------------------------

def test_approving_one_category_does_not_activate_another():
    templates = {"recruit_intro": REAL_BODY, "parent": REAL_BODY,
                 "camp_inquiry": REAL_BODY}
    approvals = TemplateApprovals(name_only={"recruit_intro"})

    approved = _plan(templates, approvals, category="recruit_intro")
    assert approved["template"] == REAL_BODY

    for other in ("parent", "camp_inquiry"):
        plan = _plan(templates, approvals, category=other, year="unknown")
        assert plan["template"] is None, (
            f"approving recruit_intro silently activated {other}"
        )
        assert "template unapproved" in plan["draft_skip"]
        assert other in plan["draft_skip"]


def test_year_variant_is_approved_independently_of_its_category():
    """recruit_intro_2027 is different wording from recruit_intro, so
    approving the generic file must not silently approve the year file."""
    templates = {"recruit_intro_2027": "year specific wording"}
    plan = _plan(templates, TemplateApprovals(name_only={"recruit_intro"}))

    assert plan["template"] is None
    assert "recruit_intro_2027" in plan["draft_skip"]


# --------------------------------------------------------------------
# Content binding: approval must not survive an edit.
# --------------------------------------------------------------------

def test_content_bound_approval_matches_exact_wording():
    approvals = TemplateApprovals(
        content_bound={"recruit_intro": template_digest(REAL_BODY)}
    )
    plan = _plan({"recruit_intro": REAL_BODY}, approvals)
    assert plan["template"] == REAL_BODY


def test_editing_an_approved_template_revokes_its_approval():
    """Approval is bound to reviewed wording, not to a category name."""
    approvals = TemplateApprovals(
        content_bound={"recruit_intro": template_digest(REAL_BODY)}
    )
    edited = REAL_BODY + "\nP.S. come to camp, bring a deposit."

    plan = _plan({"recruit_intro": edited}, approvals)

    assert plan["template"] is None, (
        "edited template kept its old approval - wording is not pinned"
    )
    assert "wording changed since it was reviewed" in plan["draft_skip"]


# --------------------------------------------------------------------
# Approval can never override the placeholder block.
# --------------------------------------------------------------------

@pytest.mark.parametrize("approvals", [
    TemplateApprovals(name_only={"recruit_intro"}),
    TemplateApprovals(content_bound={
        "recruit_intro": template_digest("[PLACEHOLDER TEMPLATE - x]\nbody")
    }),
])
def test_approval_cannot_unlock_a_placeholder_template(approvals):
    plan = _plan({"recruit_intro": "[PLACEHOLDER TEMPLATE - x]\nbody"}, approvals)

    assert plan["template"] is None
    assert "placeholder unsafe" in plan["draft_skip"]


# --------------------------------------------------------------------
# Artifact parsing and account/label binding.
#
# Binding mirrors campaign.load_campaign_approval: the artifact names the
# Gmail account it was reviewed for, and that must match the authenticated
# account. Without it an approval reviewed on the test account would
# authorize drafting in the coach's real mailbox.
# --------------------------------------------------------------------

ACCOUNT = "coach@example.edu"


def _artifact(tmp_path, **overrides):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "approved_templates": {"recruit_intro": template_digest(REAL_BODY)},
    }
    document.update(overrides)
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_load_template_approval_roundtrip(tmp_path):
    path = _artifact(tmp_path)
    assert load_template_approval(path, ACCOUNT) == {
        "recruit_intro": template_digest(REAL_BODY)
    }
    assert load_template_approval(None, ACCOUNT) == {}


def test_approval_is_rejected_for_a_different_account(tmp_path):
    """THE portability guard: a test-account artifact must not authorize
    drafting in the coach's mailbox."""
    path = _artifact(tmp_path)
    with pytest.raises(ValueError, match="account does not match"):
        load_template_approval(path, "someone-else@example.test")


def test_approval_accepts_the_matching_account_case_insensitively(tmp_path):
    path = _artifact(tmp_path)
    assert load_template_approval(path, "Coach@Example.EDU")
    assert load_template_approval(path, "Coach <coach@example.edu>")


def test_account_is_required_in_the_artifact(tmp_path):
    path = _artifact(tmp_path)
    document = json.loads(open(path).read())
    document.pop("account")
    open(path, "w").write(json.dumps(document))
    with pytest.raises(ValueError, match="must name the Gmail account"):
        load_template_approval(path, ACCOUNT)


def test_label_scoped_approval_matches_only_that_label(tmp_path):
    path = _artifact(tmp_path, label="YEAR_LABEL")

    assert load_template_approval(path, ACCOUNT, "YEAR_LABEL")
    with pytest.raises(ValueError, match="label does not match"):
        load_template_approval(path, ACCOUNT, "Other")


def test_label_scoped_approval_refuses_a_run_with_no_single_label(tmp_path):
    """The daily processor scans a query, not one label. An artifact scoped
    to a label must be refused there rather than silently widened."""
    path = _artifact(tmp_path, label="YEAR_LABEL")
    with pytest.raises(ValueError, match="does not target a single label"):
        load_template_approval(path, ACCOUNT, None)


def test_unlabeled_approval_applies_within_its_account(tmp_path):
    path = _artifact(tmp_path)
    assert load_template_approval(path, ACCOUNT, "AnyLabel")
    assert load_template_approval(path, ACCOUNT, None)


def test_precheck_validates_structure_without_authorizing_anything(tmp_path):
    """precheck runs before Gmail contact, so it cannot know the account.
    It must still reject malformed files - and must never be mistaken for
    the binding check."""
    good = _artifact(tmp_path)
    assert precheck_template_approval(good) is None
    assert precheck_template_approval(None) is None

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 1, "approved_templates": {}}))
    with pytest.raises(ValueError):
        precheck_template_approval(str(bad))


@pytest.mark.parametrize("document", [
    {"version": 2, "account": ACCOUNT, "approved_templates": {"a": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT},
    {"version": 1, "account": ACCOUNT, "approved_templates": {}},
    {"version": 1, "account": ACCOUNT, "approved_templates": {"a": "not-a-digest"}},
    {"version": 1, "account": ACCOUNT, "approved_templates": {"a": "sha256:tooshort"}},
    {"version": 1, "account": ACCOUNT, "approved_templates": {"": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT, "approved_templates": []},
    {"version": 1, "account": "", "approved_templates": {"a": "sha256:" + "a" * 64}},
    {"version": 1, "account": 42, "approved_templates": {"a": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT, "label": "",
     "approved_templates": {"a": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT, "label": 7,
     "approved_templates": {"a": "sha256:" + "a" * 64}},
])
def test_malformed_approval_artifacts_are_rejected(tmp_path, document):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        load_template_approval(str(path), ACCOUNT)


def test_build_template_approvals_combines_both_sources(tmp_path):
    path = _artifact(tmp_path)

    approvals = build_template_approvals(path, {"parent"}, ACCOUNT)

    assert approvals.approved_keys() == ["parent", "recruit_intro"]
    assert approvals.check("recruit_intro", REAL_BODY)[0] is True
    assert approvals.check("parent", "anything at all")[0] is True
    assert approvals.check("camp_inquiry", REAL_BODY)[0] is False


def test_build_template_approvals_enforces_the_account_binding(tmp_path):
    path = _artifact(tmp_path)
    with pytest.raises(ValueError, match="account does not match"):
        build_template_approvals(path, set(), "wrong@example.test")


# --------------------------------------------------------------------
# The scheduled path must not bypass the gate through a wiring mistake.
# daily_triage.py is what the launchd plist runs with --apply --yes, so a
# dropped keyword there would silently re-enable unreviewed drafting.
# --------------------------------------------------------------------

def test_daily_triage_defaults_to_no_template_approval():
    import daily_triage

    args = daily_triage.parse_args(["daily"])
    assert args.template_approval is None
    assert args.templates_approved is None

    approvals = build_template_approvals(
        args.template_approval,
        __import__("triage").parse_approved_names(args.templates_approved),
        "coach@example.edu",
    )
    assert approvals.approved_keys() == [], (
        "scheduled runs must start with nothing approved"
    )


def test_daily_triage_passes_template_approvals_into_plan_message():
    """Static guard: the scheduled pipeline's plan_message call must forward
    template_approvals. Asserted on the source so deleting the keyword fails
    here rather than silently drafting unreviewed wording at 6 PM."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "plan_message"
    ]
    assert calls, "expected daily_triage.py to call plan_message"
    for call in calls:
        keywords = {kw.arg for kw in call.keywords}
        assert "template_approvals" in keywords, (
            f"daily_triage.py:{call.lineno} calls plan_message without "
            "template_approvals; the scheduled path would bypass the gate"
        )


# NOTE: the account-binding wiring guard that used to live here now lives
# in test_approval_wiring.py, which covers campaign.py as well and also
# checks the approval path argument and definition-site defaults. Keeping
# one authoritative guard avoids the two drifting apart.


def test_shipped_templates_draft_nothing_even_if_approved():
    """Every shipped template is still a placeholder, so even a blanket
    approval of all of them must produce no draft."""
    templates = load_templates("templates")
    assert templates, "expected shipped templates"

    approvals = TemplateApprovals(name_only=set(templates))
    for category in sorted(templates):
        body, key, reason = resolve_template(
            templates, category, "unknown", "templates", approvals=approvals
        )
        assert body is None, f"{category} drafted despite being a placeholder"
        assert key is None
        assert reason
