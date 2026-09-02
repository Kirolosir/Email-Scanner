"""Offline tests for ambiguous and low-confidence classification.

The rule under test, enforced in triage.plan_message:

  * ``classification_actionable = classification_valid and confidence == "high"``
    (triage.py). When that is False the labeler is handed a rewritten
    classification with category/grad_year/sender_type forced to "unknown",
    so no category label and no year label can be applied.
  * The draft chain independently refuses: ``not classification_valid`` ->
    "classification was invalid or ambiguous; not drafting", and
    ``confidence != "high"`` -> "classification confidence is not high;
    not drafting".

Both halves are asserted here - no draft AND no category label - because a
test that only checked the draft would pass even if a wrong label were still
being written to a real mailbox.

A high-confidence control case is included so these cannot pass vacuously
because drafting or labeling is broken outright.
"""
import pytest

from triage import TemplateApprovals, plan_message

YEAR_LABELS = {"2027": "YEAR_LABEL"}
CATEGORY_LABELS = {
    "recruit_intro": "Triage/Recruit Intro",
    "parent": "Triage/Parent",
    "camp_inquiry": "Triage/Camp Inquiry",
    "other": "Triage/Other",
}
REAL_TEMPLATE = "Reviewed reply wording."
TEMPLATES = {
    "recruit_intro": REAL_TEMPLATE,
    "parent": REAL_TEMPLATE,
    "camp_inquiry": REAL_TEMPLATE,
    "other": REAL_TEMPLATE,
}
APPROVED = TemplateApprovals(name_only=set(TEMPLATES))

# Deliberately vague: no category signal, no year signal, no self-identification.
VAGUE_BODY = (
    "Hi Coach, quick question about the thing we talked about. "
    "Let me know when you get a chance. Thanks!"
)


def _email(body=VAGUE_BODY, **overrides):
    value = {
        "message_id": "m1", "from": "someone@example.test",
        "subject": "Question", "body": body,
        "thread_id": "t1", "rfc_message_id": "<m1@mail>",
        "label_names": [],
    }
    value.update(overrides)
    return value


def _result(category="recruit_intro", year="2027", sender="recruit",
            confidence="high", valid=True):
    return {
        "category": category, "grad_year": year, "sender_type": sender,
        "confidence": confidence, "evidence": "", "reason": "seeded",
        "valid": valid,
    }


def _plan(result, body=VAGUE_BODY):
    return plan_message(
        _email(body), TEMPLATES, YEAR_LABELS, CATEGORY_LABELS,
        no_label=False, classifier=lambda _e: result,
        template_approvals=APPROVED,
    )


# --------------------------------------------------------------------
# Control: without this, every assertion below could pass vacuously.
# --------------------------------------------------------------------

def test_control_high_confidence_clear_message_does_draft_and_label():
    plan = _plan(_result(), body="I am in the Class of 2027 and want to join.")

    assert plan["template"] == REAL_TEMPLATE, (
        "control case must draft, or the negative tests prove nothing"
    )
    assert "Triage/Recruit Intro" in plan["decision"].add
    assert plan["draft_skip"] is None


# --------------------------------------------------------------------
# Low / medium confidence: no draft, no category label.
# --------------------------------------------------------------------

@pytest.mark.parametrize("confidence", ["low", "medium"])
def test_vague_email_with_low_confidence_drafts_nothing_and_labels_nothing(
    confidence,
):
    plan = _plan(_result(confidence=confidence))

    assert plan["template"] is None, "low-confidence message must not draft"
    assert plan["draft_skip"] == (
        "classification confidence is not high; not drafting"
    )
    assert plan["decision"].add == [], (
        f"{confidence}-confidence classification applied labels "
        f"{plan['decision'].add}; risky labeling must be suppressed too"
    )
    assert plan["decision"].conflicts == []


@pytest.mark.parametrize("confidence", ["low", "medium"])
def test_low_confidence_never_applies_a_category_label_for_any_category(
    confidence,
):
    """Sweep every real category, not just the recruiting ones."""
    for category, label in CATEGORY_LABELS.items():
        sender = {"recruit_intro": "recruit", "parent": "parent",
                  "camp_inquiry": "other", "other": "other"}[category]
        plan = _plan(_result(category=category, sender=sender,
                             year="unknown", confidence=confidence))
        assert plan["template"] is None, f"{category} drafted at {confidence}"
        assert label not in plan["decision"].add, (
            f"{category} received {label!r} at {confidence} confidence"
        )
        assert plan["decision"].add == []


# --------------------------------------------------------------------
# No clear category match.
# --------------------------------------------------------------------

@pytest.mark.parametrize("category", ["unknown", "", "invented_category",
                                      "RECRUIT_INTRO_TYPO"])
def test_message_matching_no_real_category_drafts_nothing(category):
    plan = _plan(_result(category=category, year="unknown", sender="unknown"))

    assert plan["category"] == "unknown", (
        f"{category!r} must normalize to 'unknown', got {plan['category']!r}"
    )
    assert plan["template"] is None
    assert plan["decision"].add == []


def test_classifier_marking_its_own_result_invalid_blocks_draft_and_labels():
    plan = _plan(_result(valid=False))

    assert plan["template"] is None
    assert plan["draft_skip"] == (
        "classification was invalid or ambiguous; not drafting"
    )
    assert plan["decision"].add == []


def test_sender_type_contradicting_category_is_treated_as_invalid():
    """A 'recruit_intro' whose sender is a parent is internally inconsistent;
    it must not be trusted enough to draft or label."""
    plan = _plan(_result(category="recruit_intro", sender="parent"))

    assert plan["classification"]["valid"] is False
    assert plan["template"] is None
    assert plan["decision"].add == []


# --------------------------------------------------------------------
# Ambiguity in the message text itself.
# --------------------------------------------------------------------

def test_two_conflicting_years_in_body_block_the_year_label_and_draft():
    plan = _plan(
        _result(),
        body="I am in the Class of 2027, though my brother is a 2028 recruit.",
    )

    assert "YEAR_LABEL" not in plan["decision"].add, (
        "ambiguous year evidence must not produce a year label"
    )
    assert plan["template"] is None
    assert plan["draft_skip"] == (
        "graduation-year evidence requires manual review; not drafting"
    )


def test_vague_body_with_confident_year_claim_still_gets_no_year_label():
    """High confidence from the model, but the vague body contains no
    deterministic year evidence, so the year label must not be applied."""
    plan = _plan(_result())

    assert "YEAR_LABEL" not in plan["decision"].add
    assert plan["template"] is None


# --------------------------------------------------------------------
# Empty / meaningless content.
# --------------------------------------------------------------------

@pytest.mark.parametrize("body", ["", "   ", "\n\n"])
def test_empty_body_is_suppressed_before_classification(body):
    plan = _plan(_result(), body=body)

    assert plan["classification_called"] is False, (
        "an empty message must not be sent to the classifier at all"
    )
    assert plan["template"] is None
    assert plan["decision"].add == []
