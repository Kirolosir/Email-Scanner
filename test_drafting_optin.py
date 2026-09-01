"""Offline tests for per-category drafting opt-in and AI-drafting approval.

Overall property: enabling drafting is a per-category decision, but no generic
mode can produce text without a separate account/category-bound approval.
"""
import json

import pytest

import drafting
from account_profile import AccountProfile, load_profile
from drafting import (
    AI_DRAFTING_ACKNOWLEDGEMENT,
    AI_BANNER,
    AiDraftingApprovals,
    MODE_GENERIC,
    MODE_OFF,
    MODE_TEMPLATE,
    DraftingConfigError,
    build_generic_body,
    carries_banner,
    confirm_bulk_at_runtime,
    expected_bulk_phrase,
    is_unreviewed_bulk,
    load_ai_drafting_approval,
    resolve_mode,
    validate_bulk_acknowledgement,
    validate_drafting_modes,
)
from taxonomy import TaxonomyConfirmation, proposal_digest
from triage import TemplateApprovals, plan_message

ACCOUNT = "owner@example.test"
REAL_TEMPLATE = "Reviewed wording."


def _profile(modes, slugs=("recruiting",), protected=()):
    entries = tuple(
        {
            "slug": slug, "display": slug.title(),
            "description": f"{slug} mail", "examples": [f"{slug} subject"],
            "label": f"Triage/{slug.title()}",
            "digest": proposal_digest(slug, f"{slug} mail", [f"{slug} subject"]),
        }
        for slug in slugs
    )
    return AccountProfile(
        account=ACCOUNT, timezone="UTC",
        categories=frozenset(slugs), taxonomy=entries,
        drafting_modes=dict(modes),
        protected_labels=frozenset(protected),
    )


def _confirmed(profile):
    return TaxonomyConfirmation(
        account=ACCOUNT,
        confirmed={e["slug"]: e["digest"] for e in profile.taxonomy},
    )


def _plan(profile, category="recruiting", confirmation=None,
          ai_approvals=None, draft_generator=None):
    email = {
        "message_id": "m1", "from": "a@b.test", "subject": "s",
        "body": "Real message content here.", "thread_id": "t1",
        "rfc_message_id": "<m@x>", "label_names": [],
    }
    return plan_message(
        email, {category: REAL_TEMPLATE}, {},
        {slug: f"Triage/{slug.title()}" for slug in profile.categories},
        no_label=False,
        classifier=lambda _e: {"category": category, "grad_year": "unknown",
                               "sender_type": "other", "confidence": "high"},
        template_approvals=TemplateApprovals(name_only={category}),
        taxonomy_confirmation=confirmation or _confirmed(profile),
        profile=profile,
        ai_drafting_approvals=ai_approvals,
        draft_generator=draft_generator,
    )


# --------------------------------------------------------------------
# D1 / D2 / D6: opt-in is per category and fails closed
# --------------------------------------------------------------------

def test_drafting_is_off_by_default_for_every_category():
    """D1. A confirmed taxonomy with no drafting decision drafts nothing."""
    profile = _profile({"recruiting": MODE_OFF})
    plan = _plan(profile)

    assert plan["template"] is None
    assert "drafting is not enabled" in plan["draft_skip"]
    assert plan["decision"].add == ["Triage/Recruiting"], (
        "labeling must continue for a category left disabled"
    )


def test_category_absent_from_modes_defaults_to_off():
    """D1. Omission is not permission."""
    profile = _profile({"other": MODE_TEMPLATE}, slugs=("recruiting", "other"))
    plan = _plan(profile, "recruiting")

    assert plan["template"] is None
    assert "drafting is not enabled" in plan["draft_skip"]


@pytest.mark.parametrize("bad_mode", ["", "on", "TEMPLATE", "enabled",
                                      "generic ", None, 1])
def test_unknown_drafting_mode_fails_closed(bad_mode):
    """D2. An unrecognized mode must never resolve to something that drafts."""
    profile = _profile({"recruiting": bad_mode})
    assert resolve_mode(profile, "recruiting") == MODE_OFF

    plan = _plan(profile)
    assert plan["template"] is None


def test_enabling_one_category_does_not_enable_others():
    """D6."""
    profile = _profile(
        {"recruiting": MODE_TEMPLATE, "marketing": MODE_OFF},
        slugs=("recruiting", "marketing"),
    )

    assert _plan(profile, "recruiting")["template"] == REAL_TEMPLATE
    other = _plan(profile, "marketing")
    assert other["template"] is None
    assert "drafting is not enabled" in other["draft_skip"]


def test_template_mode_still_requires_wording_approval():
    """D3. Opting in does not bypass the wording-bound gate."""
    profile = _profile({"recruiting": MODE_TEMPLATE})
    email = {
        "message_id": "m1", "from": "a@b.test", "subject": "s",
        "body": "Real message content here.", "thread_id": "t1",
        "rfc_message_id": "<m@x>", "label_names": [],
    }
    plan = plan_message(
        email, {"recruiting": REAL_TEMPLATE}, {},
        {"recruiting": "Triage/Recruiting"}, no_label=False,
        classifier=lambda _e: {"category": "recruiting",
                               "grad_year": "unknown",
                               "sender_type": "other", "confidence": "high"},
        template_approvals=None,          # no approval supplied
        taxonomy_confirmation=_confirmed(profile),
        profile=profile,
    )

    assert plan["template"] is None
    assert "template unapproved" in plan["draft_skip"]


def test_generic_mode_still_requires_taxonomy_confirmation():
    """D8. Opting into free-form does not skip the taxonomy gate."""
    profile = _profile({"recruiting": MODE_GENERIC})
    plan = _plan(profile, confirmation=TaxonomyConfirmation(account=ACCOUNT))

    assert plan["template"] is None
    assert "taxonomy unconfirmed" in plan["draft_skip"]


def test_generic_mode_generates_without_a_template_or_template_digest():
    profile = _profile({"recruiting": MODE_GENERIC})
    approvals = AiDraftingApprovals(
        account=ACCOUNT, categories={"recruiting"}
    )
    calls = []

    def generate(email, classification, actual_profile):
        calls.append((email["subject"], classification["category"], actual_profile))
        return "Thanks for reaching out. I will review your note."

    plan = _plan(
        profile,
        ai_approvals=approvals,
        draft_generator=generate,
    )

    assert plan["template"].startswith(AI_BANNER)
    assert "Thanks for reaching out" in plan["template"]
    assert plan["template_key"] == "ai:recruiting"
    assert plan["draft_source"] == "ai"
    assert plan["draft_generation_called"] is True
    assert calls and calls[0][2] is profile


def test_generic_mode_without_ai_approval_never_calls_generator():
    profile = _profile({"recruiting": MODE_GENERIC})
    calls = []
    plan = _plan(
        profile,
        ai_approvals=AiDraftingApprovals(account=ACCOUNT),
        draft_generator=lambda *_args: calls.append(True),
    )

    assert plan["template"] is None
    assert "not approved" in plan["draft_skip"]
    assert calls == []


def test_generic_generator_failure_isolated_to_message():
    profile = _profile({"recruiting": MODE_GENERIC})
    plan = _plan(
        profile,
        ai_approvals=AiDraftingApprovals(
            account=ACCOUNT, categories={"recruiting"}
        ),
        draft_generator=lambda *_args: (_ for _ in ()).throw(RuntimeError("x")),
    )

    assert plan["template"] is None
    assert plan["draft_generation_error"] == "RuntimeError"
    assert "failed safely" in plan["draft_skip"]


def test_protected_message_requires_separate_permission():
    profile = _profile(
        {"recruiting": MODE_GENERIC}, protected={"Triage/Recruiting"}
    )
    blocked = _plan(
        profile,
        ai_approvals=AiDraftingApprovals(
            account=ACCOUNT, categories={"recruiting"},
            allow_protected_labels=False,
        ),
        draft_generator=lambda *_args: "Body",
    )
    assert blocked["template"] is None
    assert "protected-label" in blocked["draft_skip"]

    allowed = _plan(
        profile,
        ai_approvals=AiDraftingApprovals(
            account=ACCOUNT, categories={"recruiting"},
            allow_protected_labels=True,
        ),
        draft_generator=lambda *_args: "Body",
    )
    assert allowed["draft_source"] == "ai"


def test_ai_drafting_approval_is_account_and_category_bound(tmp_path):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "approved_categories": ["recruiting"],
        "allow_protected_labels": True,
        "acknowledgement": AI_DRAFTING_ACKNOWLEDGEMENT,
    }
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(document))

    approval = load_ai_drafting_approval(
        str(path), ACCOUNT, {"recruiting", "parent"}
    )
    assert approval.categories == {"recruiting"}
    assert approval.allow_protected_labels is True

    with pytest.raises(DraftingConfigError, match="account does not match"):
        load_ai_drafting_approval(
            str(path), "different@example.test", {"recruiting"}
        )
    with pytest.raises(DraftingConfigError, match="outside the account taxonomy"):
        load_ai_drafting_approval(str(path), ACCOUNT, {"parent"})


def test_model_output_cannot_select_the_drafting_mode():
    """D7. The mode comes from config, never from the classifier."""
    profile = _profile({"recruiting": MODE_OFF})
    email = {
        "message_id": "m1", "from": "a@b.test", "subject": "s",
        "body": "Real message content here.", "thread_id": "t1",
        "rfc_message_id": "<m@x>", "label_names": [],
    }
    plan = plan_message(
        email, {"recruiting": REAL_TEMPLATE}, {},
        {"recruiting": "Triage/Recruiting"}, no_label=False,
        classifier=lambda _e: {
            "category": "recruiting", "grad_year": "unknown",
            "sender_type": "other", "confidence": "high",
            # A model trying to turn itself on.
            "drafting": {"mode": "generic"}, "mode": "generic",
        },
        template_approvals=TemplateApprovals(name_only={"recruiting"}),
        taxonomy_confirmation=_confirmed(profile),
        profile=profile,
    )

    assert plan["template"] is None
    assert "drafting is not enabled" in plan["draft_skip"]


# --------------------------------------------------------------------
# D4 / D5: the AI banner
# --------------------------------------------------------------------

def test_generic_draft_always_carries_the_banner():
    """D4."""
    body = build_generic_body("Thanks for reaching out, we'll be in touch.")

    assert body.startswith(AI_BANNER)
    assert carries_banner(body)
    assert "AI-DRAFTED" in body
    assert "No human has read this text" in body
    assert "Thanks for reaching out" in body


@pytest.mark.parametrize("model_text", ["", "   ", None])
def test_empty_model_output_is_refused(model_text):
    with pytest.raises(DraftingConfigError, match="no reply text"):
        build_generic_body(model_text)


def test_banner_is_not_config_supplied():
    """D5. A config-supplied banner could be set to the empty string, which
    is exactly what the banner exists to prevent - so it is a code constant
    and no profile field can override it."""
    profile_fields = set(AccountProfile.__dataclass_fields__)
    banner_like = {
        name for name in profile_fields
        if "banner" in name or "tag_text" in name or "disclaimer" in name
    }
    assert banner_like == set(), (
        f"profile exposes banner text as configuration: {banner_like}"
    )
    assert AI_BANNER.strip(), "the banner constant must not be empty"


# --------------------------------------------------------------------
# Protected labels require explicit AI-drafting permission
# --------------------------------------------------------------------

def test_generic_mode_can_be_configured_for_a_protected_category():
    """Configuration is separate from runtime account/category approval."""
    assert validate_drafting_modes(
        {"recruiting": MODE_GENERIC}, {"recruiting"},
        protected_categories={"recruiting"},
    )


def test_validate_rejects_unknown_modes_and_unknown_categories():
    with pytest.raises(DraftingConfigError, match="unsupported drafting mode"):
        validate_drafting_modes({"a": "sometimes"}, {"a"})
    with pytest.raises(DraftingConfigError, match="unknown category"):
        validate_drafting_modes({"ghost": MODE_OFF}, {"a"})


# --------------------------------------------------------------------
# U1-U5: the unreviewed-bulk configuration
# --------------------------------------------------------------------

def test_unsafe_shape_is_detected_across_category_counts():
    """U2."""
    for count in (1, 3, 8):
        modes = {f"c{i}": MODE_GENERIC for i in range(count)}
        assert is_unreviewed_bulk(modes, protected_labels=()) is True

    # A protected label must not make the risky shape disappear.
    assert is_unreviewed_bulk({"a": MODE_GENERIC}, protected_labels={"X"}) is True
    assert is_unreviewed_bulk({"a": MODE_GENERIC, "b": MODE_OFF}, ()) is False
    assert is_unreviewed_bulk({}, ()) is False


def test_all_generic_no_protection_is_refused_without_acknowledgement():
    """U1."""
    with pytest.raises(DraftingConfigError, match="removes every review layer"):
        validate_bulk_acknowledgement(None, ACCOUNT, 3)


def test_acknowledgement_rejected_for_a_different_account():
    """U3."""
    ack = {
        "account": "someone@else.test", "category_count": 2,
        "phrase": expected_bulk_phrase("someone@else.test", 2),
    }
    with pytest.raises(DraftingConfigError, match="different account"):
        validate_bulk_acknowledgement(ack, ACCOUNT, 2)


def test_acknowledgement_phrase_must_match_exactly():
    """U4. No case-insensitive or substring matching."""
    good = expected_bulk_phrase(ACCOUNT, 2)
    base = {"account": ACCOUNT, "category_count": 2}

    assert validate_bulk_acknowledgement({**base, "phrase": good}, ACCOUNT, 2)

    for wrong in (good.upper(), good.lower(), good + " ", " " + good,
                  good.replace("all", "ALL"), good[:-1], "yes", ""):
        if wrong == good:
            continue
        with pytest.raises(DraftingConfigError, match="phrase does not match"):
            validate_bulk_acknowledgement({**base, "phrase": wrong}, ACCOUNT, 2)


def test_acknowledgement_is_bound_to_the_category_count():
    """An acknowledgement must not survive the taxonomy growing."""
    ack = {"account": ACCOUNT, "category_count": 2,
           "phrase": expected_bulk_phrase(ACCOUNT, 2)}
    with pytest.raises(DraftingConfigError, match="different number"):
        validate_bulk_acknowledgement(ack, ACCOUNT, 3)


def test_yes_flag_does_not_bypass_bulk_acknowledgement():
    """U5. --yes skips routine prompts, never the one confirmation that
    exists because every other safeguard was removed."""
    refused = confirm_bulk_at_runtime(
        ACCOUNT, 3, reader=lambda _p: "yes", assume_yes=True
    )
    assert refused is False, "--yes bypassed the unreviewed-bulk gate"

    accepted = confirm_bulk_at_runtime(
        ACCOUNT, 3,
        reader=lambda _p: expected_bulk_phrase(ACCOUNT, 3),
        assume_yes=False,
    )
    assert accepted is True


def test_bulk_gate_cannot_be_scripted_without_a_tty():
    def no_input(_prompt):
        raise EOFError
    assert confirm_bulk_at_runtime(ACCOUNT, 2, reader=no_input) is False


# --------------------------------------------------------------------
# End to end through the config loader
# --------------------------------------------------------------------

def _config(tmp_path, **overrides):
    document = {
        "version": 1, "account": ACCOUNT, "timezone": "UTC",
        "taxonomy": [
            {"slug": "recruiting", "label": "Triage/Recruiting",
             "drafting": {"mode": "template"}},
            {"slug": "marketing", "label": "Triage/Marketing"},
        ],
    }
    document.update(overrides)
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_loaded_config_gives_every_category_an_explicit_mode(tmp_path):
    """No loaded config may reach the runtime ungoverned."""
    profile = load_profile(_config(tmp_path))

    assert set(profile.drafting_modes) == profile.categories
    assert profile.drafting_modes["recruiting"] == MODE_TEMPLATE
    assert profile.drafting_modes["marketing"] == MODE_OFF


def test_loaded_config_allows_generic_on_a_protected_category_with_bulk_ack(tmp_path):
    phrase = expected_bulk_phrase(ACCOUNT, 1)
    path = _config(
        tmp_path,
        taxonomy=[{"slug": "recruiting", "label": "Triage/Recruiting",
                   "drafting": {"mode": "generic"}}],
        protected_labels=[{"label": "Triage/Recruiting"}],
        unreviewed_bulk_acknowledgement={
            "account": ACCOUNT, "category_count": 1, "phrase": phrase,
        },
    )
    assert load_profile(path).drafting_modes["recruiting"] == MODE_GENERIC


def test_loaded_all_generic_config_relies_on_separate_runtime_ai_approval(tmp_path):
    path = _config(tmp_path, taxonomy=[
        {"slug": "a", "label": "Triage/A", "drafting": {"mode": "generic"}},
        {"slug": "b", "label": "Triage/B", "drafting": {"mode": "generic"}},
    ])
    profile = load_profile(path)
    assert set(profile.drafting_modes.values()) == {MODE_GENERIC}

    # The legacy duplicate acknowledgement remains accepted, but permission
    # to generate is now exclusively checked by AiDraftingApprovals.
    ok = _config(
        tmp_path,
        taxonomy=[
            {"slug": "a", "label": "Triage/A", "drafting": {"mode": "generic"}},
            {"slug": "b", "label": "Triage/B", "drafting": {"mode": "generic"}},
        ],
        unreviewed_bulk_acknowledgement={
            "account": ACCOUNT, "category_count": 2,
            "phrase": expected_bulk_phrase(ACCOUNT, 2),
        },
    )
    profile = load_profile(ok)
    assert set(profile.drafting_modes.values()) == {MODE_GENERIC}


def test_legacy_profile_has_no_drafting_modes():
    """The code-defined profile does not use per-category drafting control,
    which is why pass one and two behavior is unchanged."""
    legacy = load_profile()
    assert dict(legacy.drafting_modes) == {}
    assert resolve_mode(legacy, "parent") is None


def test_comment_key_is_allowed_but_typos_are_still_rejected(tmp_path):
    """The shipped example explains itself in the file a reader is looking
    at, so "_comment" is permitted. Strictness matters more than the comment
    though: any other unknown key must still fail loudly, or a typo like
    "aproved_categories" would silently approve nothing while appearing to
    approve everything."""
    base = {
        "version": 1, "account": "owner@example.test",
        "approved_categories": ["recruiting"],
        "allow_protected_labels": False,
        "acknowledgement": drafting.AI_DRAFTING_ACKNOWLEDGEMENT,
    }

    commented = tmp_path / "ok.json"
    commented.write_text(json.dumps({**base, "_comment": "explains itself"}))
    approvals = load_ai_drafting_approval(
        str(commented), "owner@example.test", {"recruiting"}
    )
    assert approvals.categories == frozenset({"recruiting"})

    for typo in ("aproved_categories", "allow_protected_label", "coment"):
        bad = tmp_path / f"{typo}.json"
        bad.write_text(json.dumps({**base, typo: []}))
        with pytest.raises(DraftingConfigError, match="unsupported"):
            load_ai_drafting_approval(
                str(bad), "owner@example.test", {"recruiting"}
            )


def test_shipped_example_is_conservative():
    """Examples get copied wholesale. The shipped one must not demonstrate
    the maximally permissive configuration."""
    document = json.load(open("ai-drafting-approval.example.json"))

    assert document["allow_protected_labels"] is False
    assert len(document["approved_categories"]) <= 2
    assert "_comment" in document and "larger grant" in document["_comment"]
