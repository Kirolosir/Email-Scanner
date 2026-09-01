"""Offline tests for gmail_labeler's decision policy. No Gmail API, no
network, no auth. Label names here are placeholders - the policy is
independent of what the real labels turn out to be called.

Run with:  pytest test_labeler_logic.py
"""
import pytest

from gmail_labeler import (
    PLACEHOLDER_CATEGORY_LABELS,
    PLACEHOLDER_YEAR_LABELS,
    apply_labels,
    build_label_index,
    decide_labels,
    fetch_account_labels,
)

# Placeholder stand-ins for whatever the account's real labels are named.
YEAR_LABELS = {"2027": "YR-2027", "2028": "YR-2028"}
CATEGORY_LABELS = {
    "recruit_intro": "CAT-Recruit",
    "parent": "CAT-Parent",
    "camp_inquiry": "CAT-Camp",
}


def decide(category, grad_year, current=(), sender_type="recruit",
           local_grad_year=None, confidence="high"):
    """`local_grad_year` defaults to agreeing with the model, which is the
    common case. Pass it explicitly to exercise disagreement."""
    return decide_labels(
        {"category": category, "grad_year": grad_year,
         "sender_type": sender_type, "confidence": confidence,
         "local_grad_year": grad_year if local_grad_year is None
                            else local_grad_year},
        current, YEAR_LABELS, CATEGORY_LABELS,
    )


# --------------------------------------------------------------------
# The labeler's own model-vs-evidence agreement check.
#
# triage.plan_message already blanks the year before calling decide_labels
# when evidence conflicts, so these cases cannot arise through that path
# today. They are asserted here anyway because decide_labels is a public
# function carrying its own documented policy: without these, deleting the
# agreement condition in gmail_labeler breaks no test at all, and the
# guarantee would rest on a single caller remembering to pre-filter.
# --------------------------------------------------------------------

def test_year_label_requires_local_evidence_to_agree_with_the_model():
    """Model says 2027 but the message text yields no year -> no year label."""
    d = decide("recruit_intro", "2027", local_grad_year="unknown")

    assert "YR-2027" not in d.add, (
        "model output alone applied a year label without agreeing evidence"
    )
    assert d.add == ["CAT-Recruit"]
    assert any("without matching deterministic" in s for s in d.skips)


def test_year_label_blocked_when_local_evidence_names_a_different_year():
    d = decide("recruit_intro", "2027", local_grad_year="2028")

    assert "YR-2027" not in d.add
    assert "YR-2028" not in d.add, "must not label the evidence year either"
    assert d.add == ["CAT-Recruit"]


def test_year_label_blocked_when_local_evidence_is_empty_string():
    d = decide("recruit_intro", "2027", local_grad_year="")

    assert "YR-2027" not in d.add
    assert d.add == ["CAT-Recruit"]


def test_year_label_applied_only_when_both_agree():
    """Control: the agreement path must still work, or the tests above
    would pass simply because year labeling is broken."""
    d = decide("recruit_intro", "2027", local_grad_year="2027")

    assert "YR-2027" in d.add


def test_labeler_independently_requires_high_confidence_for_the_year():
    d = decide("recruit_intro", "2027", local_grad_year="2027",
               confidence="low")

    assert "YR-2027" not in d.add
    assert any("confidence is not high" in s for s in d.skips)


class _FakeGmail:
    """Records the modify() body so we can assert on it."""

    def __init__(self):
        self.modify_calls = []

    def users(self):
        return self

    def messages(self):
        return self

    def labels(self):
        return self

    def list(self, userId):
        return _FakeCall({"labels": [
            {"name": "YR-2027", "id": "Label_1"},
            {"name": "CAT-Parent", "id": "Label_2"},
        ]})

    def modify(self, userId, id, body):
        self.modify_calls.append({"id": id, "body": body})
        return _FakeCall({"id": id})


class _FakeCall:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


def test_clean_message_gets_both():
    d = decide("recruit_intro", "2027")

    assert sorted(d.add) == ["CAT-Recruit", "YR-2027"]
    assert d.conflicts == []


def test_unknown_category_never_labeled():
    d = decide("unknown", "2027")

    assert d.add == [], "unknown category must add no campaign year label"
    assert any("unknown" in s for s in d.skips), "must log why it skipped"

    # Blank and 'n/a' should behave the same way.
    assert decide("", "2027").add == []
    assert decide("n/a", "2027").add == []


def test_existing_year_label_never_overwritten():
    d = decide("recruit_intro", "2028", current=["YR-2027"])

    assert d.add == ["CAT-Recruit"], "must not add a second year label"
    assert any("not overwritten" in s for s in d.skips)


def test_year_applied_only_when_extracted():
    d = decide("recruit_intro", "unknown")
    assert d.add == ["CAT-Recruit"], "no year extracted -> no year label"
    assert any("no grad year" in s for s in d.skips)

    # A year with no corresponding label must not invent one.
    d = decide("recruit_intro", "2031")
    assert d.add == ["CAT-Recruit"], "year with no existing label must skip"
    assert any("not creating one" in s for s in d.skips)


def test_category_conflict_logged_not_overwritten():
    # Classifier says camp_inquiry; message already carries CAT-Parent.
    d = decide("camp_inquiry", "2027", current=["CAT-Parent"])

    assert d.add == [], "a non-recruit category must not receive a year label"
    assert len(d.conflicts) == 1
    assert "CAT-Parent" in d.conflicts[0], "conflict must name the existing label"
    assert "CAT-Camp" in d.conflicts[0], "conflict must name the proposed label"


def test_same_category_already_present_is_noop():
    d = decide("parent", "2027", current=["CAT-Parent"], sender_type="parent")

    assert d.add == [], "already-correct category must not re-add"
    assert d.conflicts == [], "matching label is not a conflict"


def test_unmatched_category_not_created():
    d = decide("media_request", "2027")

    assert d.add == []
    assert any("not creating one" in s for s in d.skips)


def test_fully_labeled_message_is_noop():
    d = decide(
        "parent", "2027", current=["CAT-Parent", "YR-2027"],
        sender_type="parent",
    )

    assert d.add == []
    assert d.has_work is False
    assert d.conflicts == []


def test_apply_labels_adds_only():
    service = _FakeGmail()
    account = {"CAT-Recruit": "Label_9", "YR-2027": "Label_1"}
    ids = apply_labels(service, "msg1", ["CAT-Recruit", "YR-2027"], account)

    body = service.modify_calls[0]["body"]

    assert ids == ["Label_9", "Label_1"], "must resolve names to ids"
    assert body.get("addLabelIds") == ["Label_9", "Label_1"]
    assert "removeLabelIds" not in body, \
        "must never remove a label - that is the never-overwrite guarantee"

    # Empty decision should make no API call at all.
    service2 = _FakeGmail()
    assert apply_labels(service2, "m", [], account) == []
    assert service2.modify_calls == [], "no labels must mean no API call"


def test_apply_refuses_unknown_label():
    """A label not in the account list must raise, not be created."""
    service = _FakeGmail()

    with pytest.raises(KeyError):
        apply_labels(service, "msg1", ["CAT-DoesNotExist"], {"YR-2027": "L1"})

    assert service.modify_calls == [], "must not call modify before raising"


def test_fetch_account_labels():
    service = _FakeGmail()

    assert fetch_account_labels(service) == {
        "YR-2027": "Label_1",
        "CAT-Parent": "Label_2",
    }


def test_label_index_only_returns_existing_labels():
    """build_label_index must never surface a label the account lacks -
    that is what stops a placeholder name from causing a bogus apply."""
    # Account has one year label and one category label from the defaults.
    account = {
        PLACEHOLDER_YEAR_LABELS["2027"]: "L1",
        PLACEHOLDER_CATEGORY_LABELS["parent"]: "L2",
        "Some/Unrelated Label": "L3",
    }
    years, categories = build_label_index(account)

    assert years == {"2027": PLACEHOLDER_YEAR_LABELS["2027"]}
    assert categories == {"parent": PLACEHOLDER_CATEGORY_LABELS["parent"]}
    assert set(years.values()) | set(categories.values()) <= set(account), \
        "every returned label must already exist in the account"

    # An account with none of the configured labels yields nothing at all,
    # so decide_labels() skips everything rather than inventing labels.
    empty_years, empty_categories = build_label_index({"Random": "L9"})
    assert empty_years == {}
    assert empty_categories == {}

    # Explicit maps override the placeholders without editing the module.
    years2, categories2 = build_label_index(
        {"Class of 2027": "L1", "Camp Qs": "L2"},
        year_labels={"2027": "Class of 2027"},
        category_labels={"camp_inquiry": "Camp Qs"},
    )
    assert years2 == {"2027": "Class of 2027"}
    assert categories2 == {"camp_inquiry": "Camp Qs"}
