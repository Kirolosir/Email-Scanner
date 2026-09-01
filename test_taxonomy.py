"""Offline tests for taxonomy discovery, sanitization, and the confirmation
gate. Covers T1-T9 from the pre-build plan.

The property under test overall: model-proposed category names are untrusted
input. They cannot reach Gmail unsanitized, cannot collide with an existing
label, and cannot authorize drafting until the account owner has confirmed the
exact presentation they were shown.
"""
import json

import pytest

from account_profile import AccountProfile, load_profile
from taxonomy import (
    TaxonomyConfirmation,
    TaxonomyError,
    build_proposal,
    build_taxonomy,
    load_taxonomy_confirmation,
    proposal_digest,
    render_review_sheet,
    sanitize_slug,
    validate_label_name,
)
from triage import TemplateApprovals, plan_message

ACCOUNT = "owner@example.test"
REAL_TEMPLATE = "Reviewed wording."


def _discovered_profile(slugs=("recruiting", "marketing")):
    """A profile shaped like a migrated account config: it HAS a taxonomy,
    so the confirmation gate applies."""
    entries = tuple(
        {
            "slug": slug,
            "display": slug.title(),
            "description": f"{slug} mail",
            "examples": [f"{slug} subject"],
            "label": f"Triage/{slug.title()}",
            "digest": proposal_digest(slug, f"{slug} mail", [f"{slug} subject"]),
        }
        for slug in slugs
    )
    return AccountProfile(
        account=ACCOUNT,
        timezone="UTC",
        categories=frozenset(slugs),
        taxonomy=entries,
    )


def _plan(profile, confirmation, category="recruiting"):
    email = {
        "message_id": "m1", "from": "someone@example.test",
        "subject": "Hello", "body": "A message with real content in it.",
        "thread_id": "t1", "rfc_message_id": "<m1@mail>", "label_names": [],
    }
    return plan_message(
        email,
        {category: REAL_TEMPLATE},
        {}, {"recruiting": "Triage/Recruiting", "marketing": "Triage/Marketing"},
        no_label=False,
        classifier=lambda _e: {
            "category": category, "grad_year": "unknown",
            "sender_type": "other", "confidence": "high",
        },
        template_approvals=TemplateApprovals(name_only={category}),
        taxonomy_confirmation=confirmation,
        profile=profile,
    )


# --------------------------------------------------------------------
# T1 / T3 / T4: the gate itself
# --------------------------------------------------------------------

def test_unconfirmed_category_never_drafts():
    """T1. The core rule."""
    profile = _discovered_profile()
    plan = _plan(profile, TaxonomyConfirmation(account=ACCOUNT))

    assert plan["template"] is None, (
        "an unconfirmed discovered category produced a draft"
    )
    assert "taxonomy unconfirmed" in plan["draft_skip"]


def test_confirmed_category_does_draft():
    """Control: without this, T1 could pass because drafting is broken."""
    profile = _discovered_profile()
    entry = profile.taxonomy[0]
    confirmation = TaxonomyConfirmation(
        account=ACCOUNT, confirmed={entry["slug"]: entry["digest"]}
    )
    plan = _plan(profile, confirmation)

    assert plan["template"] == REAL_TEMPLATE
    assert plan["draft_skip"] is None


def test_confirming_one_category_does_not_confirm_another():
    """T3. Per-category, never global."""
    profile = _discovered_profile(("recruiting", "marketing"))
    recruiting = profile.taxonomy[0]
    confirmation = TaxonomyConfirmation(
        account=ACCOUNT, confirmed={recruiting["slug"]: recruiting["digest"]}
    )

    assert _plan(profile, confirmation, "recruiting")["template"] == REAL_TEMPLATE
    other = _plan(profile, confirmation, "marketing")
    assert other["template"] is None, (
        "confirming 'recruiting' silently enabled drafting for 'marketing'"
    )
    assert "taxonomy unconfirmed" in other["draft_skip"]


def test_unconfirmed_category_still_labels():
    """T4. Labeling is organizational and must NOT be gated - over-correcting
    here would make the confirmation step impossible to review, since the
    owner reviews the labeling log."""
    profile = _discovered_profile()
    plan = _plan(profile, TaxonomyConfirmation(account=ACCOUNT))

    assert plan["decision"].add == ["Triage/Recruiting"], (
        "labeling was blocked by the taxonomy gate; it must proceed"
    )
    assert plan["template"] is None


def test_redefining_a_category_voids_its_confirmation():
    """T2. Confirmation binds to what the owner was shown, not to a name."""
    profile = _discovered_profile()
    entry = profile.taxonomy[0]
    stale = TaxonomyConfirmation(
        account=ACCOUNT,
        confirmed={entry["slug"]: proposal_digest(
            entry["slug"], "a completely different meaning", ["other subject"]
        )},
    )
    plan = _plan(profile, stale)

    assert plan["template"] is None
    assert "changed since it was reviewed" in plan["draft_skip"]


def test_category_absent_from_the_taxonomy_never_drafts():
    profile = _discovered_profile(("recruiting",))
    entry = profile.taxonomy[0]
    confirmation = TaxonomyConfirmation(
        account=ACCOUNT, confirmed={entry["slug"]: entry["digest"]}
    )
    plan = _plan(profile, confirmation, "marketing")

    assert plan["template"] is None
    assert "not in the confirmed taxonomy" in plan["draft_skip"]


def test_code_defined_profile_is_not_gated():
    """The legacy profile's categories are code constants that went through
    code review, not model proposals. There is nothing to confirm, so the
    gate does not apply - and this is why pass one's tests still pass."""
    legacy = load_profile()

    assert legacy.taxonomy == ()
    plan = plan_message(
        {"message_id": "m1", "from": "a@b.test", "subject": "s",
         "body": "Real content here.", "thread_id": "t1",
         "rfc_message_id": "<m@x>", "label_names": []},
        {"parent": REAL_TEMPLATE}, {}, {"parent": "Triage/Parent"},
        no_label=False,
        classifier=lambda _e: {"category": "parent", "grad_year": "unknown",
                               "sender_type": "parent", "confidence": "high"},
        template_approvals=TemplateApprovals(name_only={"parent"}),
        profile=legacy,
    )
    assert plan["template"] == REAL_TEMPLATE


# --------------------------------------------------------------------
# T5 / T6 / T7: sanitization of untrusted model output
# --------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Recruiting", "recruiting"),
    ("School / Admin", "school_admin"),
    ("  Personal  ", "personal"),
    ("Marketing!!!", "marketing"),
    ("Café news", "cafe_news"),
    ("2027 recruits", "c_2027_recruits"),
    ("multi   space", "multi_space"),
])
def test_sanitize_slug_normalizes_model_names(raw, expected):
    assert sanitize_slug(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "!!!", "☃", None, 42])
def test_sanitize_slug_refuses_unusable_names(raw):
    """Refusing beats inventing a fallback: a silently renamed category is
    one the owner never reviewed."""
    with pytest.raises(TaxonomyError):
        sanitize_slug(raw)


@pytest.mark.parametrize("name", [
    "INBOX", "Inbox", "SENT", "TRASH", "SPAM", "DRAFT", "STARRED",
    "CATEGORY_PROMOTIONS", "Triage/INBOX",
])
def test_reserved_label_names_are_refused(name):
    """T6."""
    with pytest.raises(TaxonomyError):
        validate_label_name(name)


@pytest.mark.parametrize("name", [
    "", "   ", " Leading", "Trailing ", "a//b", "Triage/", "/Triage",
    "with\nnewline", "with\x00null", "x" * 226,
])
def test_malformed_label_names_are_refused(name):
    """T5."""
    with pytest.raises(TaxonomyError):
        validate_label_name(name)


def test_colliding_label_is_surfaced_not_reused():
    """T7. Writing into a label the owner already uses for something else is
    exactly what this boundary exists to prevent."""
    with pytest.raises(TaxonomyError, match="already exists"):
        validate_label_name("Triage/Recruiting",
                            existing_labels=["Triage/Recruiting"])
    with pytest.raises(TaxonomyError, match="already exists"):
        validate_label_name("triage/recruiting",
                            existing_labels=["Triage/Recruiting"])
    # A non-colliding name is fine.
    assert validate_label_name("Triage/New",
                               existing_labels=["Triage/Recruiting"])


def test_build_taxonomy_refuses_duplicate_slugs():
    with pytest.raises(TaxonomyError, match="duplicate"):
        build_taxonomy([{"name": "Recruiting"}, {"name": "recruiting!"}])


def test_build_taxonomy_refuses_an_empty_proposal_set():
    with pytest.raises(TaxonomyError):
        build_taxonomy([])


def test_proposal_digest_covers_description_and_examples():
    base = build_proposal("Recruiting", "prospects", ["subject a"])
    same = build_proposal("Recruiting", "prospects", ["subject a"])
    other_desc = build_proposal("Recruiting", "vendors", ["subject a"])
    other_ex = build_proposal("Recruiting", "prospects", ["subject b"])

    assert base["digest"] == same["digest"]
    assert base["digest"] != other_desc["digest"]
    assert base["digest"] != other_ex["digest"]


def test_review_sheet_shows_names_and_examples():
    taxonomy = build_taxonomy([
        {"name": "Recruiting", "description": "prospects",
         "examples": ["Class of 2027 midfielder"]},
    ])
    sheet = render_review_sheet(taxonomy)

    assert "Recruiting" in sheet
    assert "recruiting" in sheet
    assert "Class of 2027 midfielder" in sheet
    assert "Drafting stays blocked" in sheet


# --------------------------------------------------------------------
# T8: account binding on the confirmation artifact
# --------------------------------------------------------------------

def _artifact(tmp_path, **overrides):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "confirmed_categories": {"recruiting": proposal_digest(
            "recruiting", "recruiting mail", ["recruiting subject"]
        )},
    }
    document.update(overrides)
    path = tmp_path / "taxonomy-confirmation.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_confirmation_roundtrip(tmp_path):
    confirmation = load_taxonomy_confirmation(_artifact(tmp_path), ACCOUNT)
    assert confirmation.confirmed_slugs() == ["recruiting"]


def test_confirmation_rejected_for_a_different_account(tmp_path):
    """T8. A confirmation reviewed on one inbox must not authorize another."""
    with pytest.raises(TaxonomyError, match="does not match"):
        load_taxonomy_confirmation(_artifact(tmp_path), "someone@else.test")


def test_confirmation_requires_an_account(tmp_path):
    with pytest.raises(TaxonomyError, match="must name the account"):
        load_taxonomy_confirmation(_artifact(tmp_path, account=""), ACCOUNT)


def test_absent_confirmation_path_confirms_nothing():
    confirmation = load_taxonomy_confirmation(None, ACCOUNT)
    assert confirmation.confirmed_slugs() == []
    assert confirmation.check("recruiting", "sha256:" + "a" * 64)[0] is False


@pytest.mark.parametrize("document", [
    {"version": 2, "account": ACCOUNT, "confirmed_categories": {"a": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT},
    {"version": 1, "account": ACCOUNT, "confirmed_categories": {}},
    {"version": 1, "account": ACCOUNT, "confirmed_categories": {"A Bad Slug": "sha256:" + "a" * 64}},
    {"version": 1, "account": ACCOUNT, "confirmed_categories": {"ok": "not-a-digest"}},
    {"version": 1, "account": ACCOUNT, "confirmed_categories": []},
])
def test_malformed_confirmation_artifacts_are_rejected(tmp_path, document):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(TaxonomyError):
        load_taxonomy_confirmation(str(path), ACCOUNT)


# --------------------------------------------------------------------
# Account config loading
# --------------------------------------------------------------------

def _config(tmp_path, **overrides):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "timezone": "America/New_York",
        "taxonomy": [
            {"slug": "recruiting", "display": "Recruiting",
             "description": "prospects", "examples": ["a subject"],
             "label": "Triage/Recruiting"},
        ],
    }
    document.update(overrides)
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_account_config_loads_into_a_profile(tmp_path):
    profile = load_profile(_config(tmp_path))

    assert profile.account == ACCOUNT
    assert profile.timezone == "America/New_York"
    assert profile.categories == frozenset({"recruiting"})
    assert profile.taxonomy[0]["label"] == "Triage/Recruiting"


def test_account_config_rejects_unknown_keys(tmp_path):
    with pytest.raises(ValueError, match="unsupported account config keys"):
        load_profile(_config(tmp_path, surprise="value"))


def test_account_config_rejects_a_reserved_label(tmp_path):
    with pytest.raises(TaxonomyError):
        load_profile(_config(tmp_path, taxonomy=[
            {"slug": "x", "label": "INBOX"},
        ]))


def test_account_config_requires_account_and_timezone(tmp_path):
    with pytest.raises(ValueError, match="must name the Gmail account"):
        load_profile(_config(tmp_path, account=""))
    with pytest.raises(ValueError, match="must name a timezone"):
        load_profile(_config(tmp_path, timezone=""))


def test_account_config_taxonomy_has_no_confirmation_field(tmp_path):
    """Migration must never inherit confirmation from history: a loaded
    config carries the taxonomy but no confirmation, so the owner confirms
    fresh. This is the decision recorded in account_profile."""
    profile = load_profile(_config(tmp_path))

    for entry in profile.taxonomy:
        assert "confirmation" not in entry
    plan = _plan(profile, TaxonomyConfirmation(account=ACCOUNT))
    assert plan["template"] is None


# --------------------------------------------------------------------
# Gaps found by mutation testing pass two, closed here.
# --------------------------------------------------------------------

def test_unconfirmed_reason_names_the_specific_category():
    """T3. The digest binding already makes a wrong-slug lookup harmless, so
    the isolation is safe either way - but the logged reason must still name
    the category that was actually unconfirmed, or the confirmation step is
    reviewing misleading information."""
    profile = _discovered_profile(("recruiting", "marketing"))
    recruiting = profile.taxonomy[0]
    confirmation = TaxonomyConfirmation(
        account=ACCOUNT, confirmed={recruiting["slug"]: recruiting["digest"]}
    )

    plan = _plan(profile, confirmation, "marketing")

    assert "marketing" in plan["draft_skip"]
    assert "has not been reviewed" in plan["draft_skip"], (
        "an unreviewed category must not be reported as a changed one"
    )
    assert "recruiting" not in plan["draft_skip"]


def test_omitted_confirmation_fails_closed():
    """T9. A caller that forgets to pass a confirmation must get the
    fail-closed default, not permission. triage.py's CLI does not wire this
    argument until pass three, so this path is live today."""
    profile = _discovered_profile()
    email = {
        "message_id": "m1", "from": "a@b.test", "subject": "s",
        "body": "Real content here.", "thread_id": "t1",
        "rfc_message_id": "<m@x>", "label_names": [],
    }
    plan = plan_message(
        email, {"recruiting": REAL_TEMPLATE}, {},
        {"recruiting": "Triage/Recruiting"}, no_label=False,
        classifier=lambda _e: {"category": "recruiting",
                               "grad_year": "unknown",
                               "sender_type": "other", "confidence": "high"},
        template_approvals=TemplateApprovals(name_only={"recruiting"}),
        profile=profile,
        # taxonomy_confirmation deliberately omitted
    )

    assert plan["template"] is None, (
        "omitting the confirmation granted drafting; the default must deny"
    )
    assert "taxonomy unconfirmed" in plan["draft_skip"]


def test_slug_pattern_itself_rejects_malformed_identifiers():
    """T5. The final SLUG_PATTERN check is a backstop the normalizer makes
    hard to reach, so pin the pattern directly - otherwise loosening it is
    invisible."""
    from taxonomy import SLUG_PATTERN

    for good in ("recruiting", "school_admin", "c_2027_recruits", "a",
                 # A trailing underscore is permitted by the pattern.
                 # sanitize_slug strips them, so it never emits one, but a
                 # hand-written config slug like this is harmless.
                 "trailing_"):
        assert SLUG_PATTERN.match(good), good
    for bad in ("", "_leading", "9start", "Has Upper", "has-dash",
                "has.dot", "has space", "héllo"):
        assert not SLUG_PATTERN.match(bad), bad

    # And the sanitizer never produces the trailing form.
    assert sanitize_slug("Trailing!!!") == "trailing"


def test_reserved_names_refused_at_every_path_position():
    """T6, after removing the redundant top-level branch."""
    for name in ("INBOX", "Inbox", "Triage/INBOX", "INBOX/Sub",
                 "A/Trash/B", "CATEGORY_PROMOTIONS",
                 "Triage/CATEGORY_SOCIAL"):
        with pytest.raises(TaxonomyError):
            validate_label_name(name)
