"""Offline tests for one-time account-wide drafting activation."""
import json
import ast
from pathlib import Path

import pytest

import approve_account
from account_profile import load_profile
from drafting import (
    AI_BANNER,
    AiDraftingApprovals,
    DraftingConfigError,
    load_ai_drafting_approval,
)
from message_safety import assess_delivery_headers
from taxonomy import TaxonomyConfirmation
from triage import plan_message
from triage_limits import plans_within_draft_limit


ACCOUNT = "owner@example.test"


def _document(*, global_policy=True, signature="Owner", protected=False):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "timezone": "UTC",
        "draft_all_replyable_messages": global_policy,
        "fallback_category": "other" if global_policy else "",
        "taxonomy": [
            {
                "slug": "project",
                "description": "Project correspondence",
                "examples": ["Project update"],
                "label": "Triage/Project",
                "expected_sender": "other",
                "drafting": {"mode": "off", "guidance": "Be concise."},
            },
            {
                "slug": "other",
                "description": "Anything outside the taxonomy",
                "examples": ["General note"],
                "label": "Triage/Other",
                "expected_sender": "other",
                "drafting": {"mode": "off"},
            },
        ],
        "system_labels": {
            "needs_review": "Triage/Needs Review",
            "processed": "Triage/Processed",
        },
        "ai_drafting": {"signature": signature, "max_words": 120},
    }
    if protected:
        document["protected_labels"] = [{"label": "Recruiting/2027B"}]
        document["evidence_gated_labels"] = [{
            "label": "Recruiting/2027B",
            "pattern_set": "grad_year",
            "classifier_field": "grad_year",
            "expected_value": "2027",
            "require_sender_type": ["recruit"],
            "require_categories": ["project"],
            "min_confidence": "high",
        }]
        document["taxonomy"][0]["expected_sender"] = "recruit"
    return document


def _profile(tmp_path, **kwargs):
    path = tmp_path / "account.json"
    path.write_text(json.dumps(_document(**kwargs)), encoding="utf-8")
    return load_profile(path), path


def _confirmation(profile):
    return TaxonomyConfirmation(
        account=profile.account,
        confirmed={entry["slug"]: entry["digest"] for entry in profile.taxonomy},
    )


def _approval(profile, protected=False):
    return AiDraftingApprovals(
        account=profile.account,
        allow_protected_labels=protected,
        draft_all_replyable_messages=True,
    )


def _email(**updates):
    result = {
        "message_id": "m1",
        "from": "person@example.test",
        "subject": "Project update",
        "body": "Here is the current project update.",
        "thread_id": "t1",
        "rfc_message_id": "<m1@example.test>",
        "label_names": [],
        "own_address": ACCOUNT,
    }
    result.update(updates)
    return result


def _classification(category="project", confidence="high", valid=True,
                    year="unknown", sender="other"):
    return {
        "category": category,
        "grad_year": year,
        "sender_type": sender,
        "confidence": confidence,
        "valid": valid,
        "evidence": "offline fixture",
    }


def _plan(profile, *, email=None, result=None, approvals=None, generator=None):
    return plan_message(
        email or _email(), {}, dict(profile.year_labels),
        dict(profile.category_labels), False,
        classifier=lambda _email: result or _classification(),
        taxonomy_confirmation=_confirmation(profile),
        profile=profile,
        ai_drafting_approvals=approvals,
        draft_generator=generator,
    )


def test_global_drafting_is_off_by_default(tmp_path):
    profile, _ = _profile(tmp_path, global_policy=False)
    calls = []
    plan = _plan(
        profile, approvals=_approval(profile),
        generator=lambda *_args: calls.append(1) or "Thanks.",
    )
    assert calls == []
    assert plan["template"] is None
    assert "not enabled" in plan["draft_skip"]


def test_global_profile_requires_complete_category_and_system_labels(tmp_path):
    document = _document()
    del document["taxonomy"][0]["label"]
    path = tmp_path / "missing-category-label.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="label for every category"):
        load_profile(path)

    document = _document()
    del document["system_labels"]["needs_review"]
    path = tmp_path / "missing-review-label.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="needs_review and processed"):
        load_profile(path)


def test_missing_global_activation_makes_zero_generation_calls(tmp_path):
    profile, _ = _profile(tmp_path)
    calls = []
    plan = _plan(
        profile, approvals=None,
        generator=lambda *_args: calls.append(1) or "Thanks.",
    )
    assert calls == []
    assert plan["template"] is None
    assert "not approved" in plan["draft_skip"]


def test_zero_draft_cap_defers_global_draft_whole(tmp_path):
    profile, _ = _profile(tmp_path)
    plan = _plan(
        profile, approvals=_approval(profile),
        generator=lambda *_args: "Thank you.\n\nOwner",
    )
    admitted, deferred = plans_within_draft_limit([plan], 0)
    assert admitted == []
    assert deferred == [plan]


def test_valid_activation_drafts_even_when_category_mode_is_off(tmp_path):
    profile, _ = _profile(tmp_path)
    plan = _plan(
        profile, approvals=_approval(profile),
        generator=lambda *_args: "Thank you for the update.\n\nOwner",
    )
    assert plan["template"].startswith(AI_BANNER)
    assert plan["draft_source"] == "ai"
    assert plan["decision"].add == ["Triage/Project"]


def test_unknown_low_confidence_gets_other_review_and_neutral_draft(tmp_path):
    profile, _ = _profile(tmp_path)
    plan = _plan(
        profile,
        result=_classification("unknown", "low", False),
        approvals=_approval(profile),
        generator=lambda *_args: "Thank you for your message.\n\nOwner",
    )
    assert set(plan["decision"].add) == {
        "Triage/Other", "Triage/Needs Review",
    }
    assert plan["template"].startswith(AI_BANNER)


def test_empty_current_body_skips_classification_but_still_gets_safe_draft(tmp_path):
    profile, _ = _profile(tmp_path)
    classifier_calls = []
    generator_calls = []
    plan = plan_message(
        _email(body=""), {}, dict(profile.year_labels),
        dict(profile.category_labels), False,
        classifier=lambda _email: classifier_calls.append(1),
        taxonomy_confirmation=_confirmation(profile),
        profile=profile,
        ai_drafting_approvals=_approval(profile),
        draft_generator=lambda *_args: (
            generator_calls.append(1) or "Thank you for your message.\n\nOwner"
        ),
    )
    assert classifier_calls == []
    assert generator_calls == [1]
    assert set(plan["decision"].add) == {
        "Triage/Other", "Triage/Needs Review",
    }
    assert plan["template"] is not None


@pytest.mark.parametrize("delivery", [
    assess_delivery_headers({"from": "mailer-daemon@example.test"}),
    assess_delivery_headers({
        "from": "one@example.test",
        "reply-to": "one@example.test, two@example.test",
    }),
    assess_delivery_headers({"from": ACCOUNT}, own_address=ACCOUNT),
    assess_delivery_headers({"from": "not-an-address"}),
])
def test_unsafe_recipient_never_drafts_or_invents_address(tmp_path, delivery):
    profile, _ = _profile(tmp_path)
    calls = []
    plan = _plan(
        profile,
        email=_email(delivery_safety=delivery, reply_address=""),
        approvals=_approval(profile),
        generator=lambda *_args: calls.append(1) or "Thank you.",
    )
    assert calls == []
    assert plan["template"] is None
    assert plan["email"]["reply_address"] == ""
    assert "Triage/Needs Review" in plan["decision"].add


@pytest.mark.parametrize("headers", [
    {"from": "ASOS <news@e.asos.test>", "list-unsubscribe": "<mailto:u@e.test>"},
    {"from": "rewards@dominos.test", "precedence": "bulk"},
    {"from": "notifications@example.test", "auto-submitted": "auto-generated"},
    {"from": "no-reply@example.test"},
    {"from": "mailer-daemon@example.test"},
])
def test_automated_mail_never_drafts_even_with_a_usable_reply_address(
        tmp_path, headers):
    """The automated-message suppression must stand on its own.

    assess_delivery_headers() already blanks reply_address for automated
    mail, so the missing-reply-metadata branch would refuse these anyway.
    That redundancy is the point: this pins the suppression_code branch
    independently, so loosening the header policy later cannot silently
    make account-wide drafting start replying to newsletters, rewards
    mail, or bounces.
    """
    profile, _ = _profile(tmp_path)
    delivery = assess_delivery_headers(headers)
    assert delivery["status"] == "automated"
    calls = []

    plan = _plan(
        profile,
        # A reply address is deliberately supplied so the malformed-metadata
        # branch cannot be what refuses the draft.
        email=_email(
            delivery_safety=delivery, reply_address="person@example.test"
        ),
        approvals=_approval(profile),
        generator=lambda *_args: calls.append(1) or "Thank you.",
    )

    assert calls == [], "a generation call was made for automated mail"
    assert plan["template"] is None
    assert plan["suppression_code"] == "automated_message"
    # Asserting the specific reason, not merely that some reason exists:
    # the taxonomy gate also refuses these (an automated message classifies
    # to a category outside the taxonomy), so a looser assertion would still
    # pass with the automated-message branch deleted.
    assert "automated return path" in plan["draft_skip"]


def test_generation_retries_once_then_uses_fact_free_fallback(tmp_path):
    profile, _ = _profile(tmp_path)
    calls = []

    def rejected(*_args):
        calls.append(1)
        return "Subject: injected header"

    plan = _plan(profile, approvals=_approval(profile), generator=rejected)
    assert calls == [1, 1]
    assert plan["draft_generation_attempts"] == 2
    assert plan["draft_fallback_used"] is True
    assert plan["draft_source"] == "fallback"
    assert plan["template"] == AI_BANNER + "Thank you for your message.\n\nOwner\n"
    assert "Triage/Needs Review" in plan["decision"].add


def test_overlong_generation_is_retried_then_uses_fallback(tmp_path):
    profile, _ = _profile(tmp_path)
    calls = []
    overlong = "word " * 121
    plan = _plan(
        profile, approvals=_approval(profile),
        generator=lambda *_args: calls.append(1) or overlong,
    )
    assert calls == [1, 1]
    assert plan["draft_fallback_used"] is True
    assert overlong.strip() not in plan["template"]


def test_activation_is_account_and_configuration_digest_bound(tmp_path):
    profile, _ = _profile(tmp_path)
    _taxonomy, approval = approve_account.build_documents(profile)
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(approval), encoding="utf-8")

    loaded = load_ai_drafting_approval(
        path, ACCOUNT, profile.valid_categories, profile=profile
    )
    assert loaded.draft_all_replyable_messages is True
    with pytest.raises(DraftingConfigError, match="account"):
        load_ai_drafting_approval(
            path, "different@example.test", profile.valid_categories,
            profile=profile,
        )

    changed_path = tmp_path / "changed.json"
    changed_path.write_text(
        json.dumps(_document(signature="Changed Owner")), encoding="utf-8"
    )
    changed = load_profile(changed_path)
    with pytest.raises(DraftingConfigError, match="no longer matches"):
        load_ai_drafting_approval(
            path, ACCOUNT, changed.valid_categories, profile=changed
        )


def test_protected_label_keeps_evidence_and_permission_gates(tmp_path):
    profile, _ = _profile(tmp_path, protected=True)
    result = _classification(year="2027", sender="recruit")
    blocked = _plan(
        profile,
        email=_email(body="I am a Class of 2027 recruit."),
        result=result,
        approvals=_approval(profile, protected=False),
        generator=lambda *_args: "Thanks.",
    )
    assert "Recruiting/2027B" in blocked["decision"].add
    assert blocked["template"] is None
    assert "protected-label" in blocked["draft_skip"]

    allowed = _plan(
        profile,
        email=_email(body="I am a Class of 2027 recruit."),
        result=result,
        approvals=_approval(profile, protected=True),
        generator=lambda *_args: "Thanks.\n\nOwner",
    )
    assert allowed["template"] is not None

    unsupported = _plan(
        profile,
        email=_email(body="Our schedule continues through 2027."),
        result=result,
        approvals=_approval(profile, protected=True),
        generator=lambda *_args: "Thanks.\n\nOwner",
    )
    assert "Recruiting/2027B" not in unsupported["decision"].add


def test_global_confirmation_states_real_scope_and_cannot_be_yes(tmp_path):
    """The typed sentence must name the scope the code actually implements.

    It must not promise drafting for automated or bulk mail: the planner
    refuses those unconditionally, and a confirmation broader than the
    behavior would pre-authorize a later loosening of the delivery-header
    policy without ever asking the owner again.
    """
    profile, _ = _profile(tmp_path)
    phrase = approve_account.confirmation_phrase(
        profile, [], global_policy=True
    )
    assert "every message with a safe reply address" in phrase
    assert "excluding automated and bulk mail" in phrase
    assert profile.account in phrase
    assert phrase != "yes"
    for overpromise in ("newsletters", "advertisements", "mailing-list"):
        assert overpromise not in phrase, (
            f"the confirmation promises {overpromise!r}, which is never drafted"
        )


def test_global_activation_requires_exact_typed_phrase_and_has_no_yes(tmp_path):
    profile, config_path = _profile(tmp_path)
    taxonomy_path = tmp_path / "taxonomy.json"
    approval_path = tmp_path / "activation.json"
    argv = [
        "--account-config", str(config_path),
        "--taxonomy-output", str(taxonomy_path),
        "--ai-output", str(approval_path),
    ]
    assert approve_account.main(argv, reader=lambda _prompt: "yes") == 1
    assert not taxonomy_path.exists() and not approval_path.exists()

    phrase = approve_account.confirmation_phrase(
        profile, [], global_policy=True
    )
    assert approve_account.main(argv, reader=lambda _prompt: phrase) == 0
    document = json.loads(approval_path.read_text(encoding="utf-8"))
    assert document["version"] == 2
    assert document["draft_all_replyable_messages"] is True

    with pytest.raises(SystemExit) as caught:
        approve_account.parse_args(argv + ["--yes"])
    assert caught.value.code == 2


def test_planner_uses_runtime_global_policy_not_a_hardcoded_value():
    tree = ast.parse(Path("triage.py").read_text(encoding="utf-8"))
    planner = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "plan_message"
    )
    assignments = [
        node for node in ast.walk(planner)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "global_drafting"
            for target in node.targets
        )
    ]
    assert len(assignments) == 1
    rendered = ast.unparse(assignments[0].value)
    assert "effective_profile" in rendered
    assert "draft_all_replyable_messages" in rendered
    assert rendered not in {"True", "False", "bool(True)", "bool(False)"}


def test_real_planner_checks_approval_before_calling_global_generator():
    tree = ast.parse(Path("triage.py").read_text(encoding="utf-8"))
    planner = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "plan_message"
    )
    checks = [
        node.lineno for node in ast.walk(planner)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "check"
    ]
    generation = [
        node.lineno for node in ast.walk(planner)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_generate_global_reply"
    ]
    assert checks and generation
    assert min(checks) < min(generation)


def test_approval_cli_passes_runtime_global_policy_to_confirmation():
    tree = ast.parse(Path("approve_account.py").read_text(encoding="utf-8"))
    main = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    calls = [
        node for node in ast.walk(main)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "confirmation_phrase"
    ]
    assert len(calls) == 1
    keyword = next(
        item for item in calls[0].keywords if item.arg == "global_policy"
    )
    assert isinstance(keyword.value, ast.Name)
    assert keyword.value.id == "global_policy"
