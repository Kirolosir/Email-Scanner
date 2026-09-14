"""Offline regression tests for content, year, sender, and reply safety."""
import base64

import pytest

from gmail_reader import get_plain_text_body
from message_safety import (
    assess_delivery_headers,
    clean_current_message,
    extract_grad_year_evidence,
)
from triage import TemplateApprovals, message_to_email, plan_message


def _encoded(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _message(body, headers=None, parts=None):
    header_values = {
        "From": "Recruit <recruit@example.test>",
        "Subject": "Recruit introduction",
        "Message-ID": "<m1@example.test>",
    }
    header_values.update(headers or {})
    payload = {
        "mimeType": "text/plain",
        "headers": [{"name": key, "value": value}
                    for key, value in header_values.items()],
        "body": {"data": _encoded(body)},
    }
    if parts is not None:
        payload = {
            "mimeType": "multipart/mixed",
            "headers": payload["headers"],
            "parts": parts,
        }
    return {"id": "m1", "threadId": "t1", "payload": payload}


def _result(category="recruit_intro", year="2027", sender="recruit",
            confidence="high", valid=True):
    return {
        "category": category,
        "grad_year": year,
        "sender_type": sender,
        "confidence": confidence,
        "evidence": "model fixture",
        "reason": "offline",
        "valid": valid,
    }


@pytest.mark.parametrize("text", [
    "I am in the Class of 2027.",
    "I am a 2027 grad interested in the program.",
    "I will be graduating in 2027.",
    "Grad year: 2027",
    "I am a '27 recruit.",
])
def test_explicit_recruiting_year_evidence(text):
    result = extract_grad_year_evidence(text, supported_years={"2027"})
    assert result["grad_year"] == "2027"
    assert result["evidence_codes"]


@pytest.mark.parametrize("text", [
    "Our schedule runs through 2027.",
    "Call 202-755-2027.",
    "The event is October 27, 2027.",
    "Invoice 2027 is attached.",
])
def test_unrelated_2027_is_not_grad_year_evidence(text):
    assert extract_grad_year_evidence(
        text, supported_years={"2027"}
    )["grad_year"] == "unknown"


def test_quoted_old_year_and_signature_are_removed_before_evidence():
    cleaned = clean_current_message(
        "Thanks for the update.\n\nOn Monday Coach wrote:\n"
        "> I am a Class of 2027 recruit.\n"
    )
    assert cleaned["text"] == "Thanks for the update."
    assert extract_grad_year_evidence(
        cleaned["text"], supported_years={"2027"}
    )["grad_year"] == "unknown"

    forwarded = clean_current_message(
        "Current note.\n\nFrom: old@example.test\nSent: Monday\n"
        "To: coach@example.edu\nSubject: Class of 2027\nOld body"
    )
    assert forwarded["text"] == "Current note."


def test_cleaning_truncates_and_empty_quote_is_not_meaningful():
    truncated = clean_current_message("A" * 900, max_chars=500)
    assert len(truncated["text"]) == 500
    assert truncated["truncated"] is True
    empty = clean_current_message("> quoted only\n> Class of 2027")
    assert empty["meaningful"] is False


def test_attachment_text_is_never_extracted():
    parts = [
        {"mimeType": "text/plain", "body": {"data": _encoded("current body")}},
        {
            "mimeType": "text/plain", "filename": "private.txt",
            "body": {"data": _encoded("ATTACHMENT SECRET Class of 2027")},
        },
    ]
    body = get_plain_text_body(_message("", parts=parts))
    assert body == "current body"
    assert "ATTACHMENT" not in body


@pytest.mark.parametrize("headers,code", [
    ({"from": "MAILER-DAEMON@example.test"}, "automated_sender"),
    ({"from": "postmaster@example.test"}, "automated_sender"),
    # Bounce return paths, including the VERP forms real bounces use.
    ({"from": "bounce@example.test"}, "automated_sender"),
    ({"from": "bounces@example.test"}, "automated_sender"),
    ({"from": "bounce-123-abc@example.test"}, "automated_sender"),
    ({"from": "bounces+token@example.test"}, "automated_sender"),
])
def test_automated_headers_are_detected(headers, code):
    result = assess_delivery_headers(headers)
    assert result["status"] == "automated"
    assert code in result["reason_codes"]


@pytest.mark.parametrize("headers,target,code", [
    ({"from": "no-reply@example.test"}, "no-reply@example.test",
     "automated_sender"),
    ({"from": "person@example.test", "reply-to": "noreply@example.test"},
     "noreply@example.test", "automated_reply_target"),
])
def test_notification_addresses_remain_replyable(headers, target, code):
    result = assess_delivery_headers(headers)
    assert result["status"] == "bulk"
    assert result["reply_address"] == target
    assert code in result["reason_codes"]


@pytest.mark.parametrize("headers,code", [
    ({"from": "person@example.test", "auto-submitted": "auto-replied"},
     "auto_submitted"),
    ({"from": "person@example.test", "precedence": "bulk"},
     "bulk_precedence"),
    ({"from": "person@example.test", "list-unsubscribe": "<x>"},
     "mailing_list"),
    ({"from": "person@example.test", "x-auto-response-suppress": "All"},
     "auto_response_suppressed"),
])
def test_bulk_headers_preserve_a_safe_reply_target(headers, code):
    result = assess_delivery_headers(headers)
    assert result["status"] == "bulk"
    assert result["reply_address"] == "person@example.test"
    assert code in result["reason_codes"]


def test_no_reply_sender_with_safe_explicit_reply_to_is_replyable():
    result = assess_delivery_headers({
        "from": "no-reply@example.test",
        "reply-to": "support@example.test",
    })
    assert result["status"] == "bulk"
    assert result["reply_address"] == "support@example.test"


def test_safe_reply_to_and_unsafe_multiple_reply_to():
    safe = assess_delivery_headers({
        "from": "Sender <sender@example.test>",
        "reply-to": "Recruit <recruit@example.test>",
    })
    assert safe["status"] == "normal"
    assert safe["reply_address"] == "recruit@example.test"

    unsafe = assess_delivery_headers({
        "from": "sender@example.test",
        "reply-to": "one@example.test, two@example.test",
    })
    assert unsafe["status"] == "ambiguous"
    assert unsafe["reply_address"] == ""

    repeated = _message("Current body", headers={"Reply-To": "one@example.test"})
    repeated["payload"]["headers"].append(
        {"name": "Reply-To", "value": "two@example.test"}
    )
    assert message_to_email(repeated)["delivery_safety"]["status"] == "ambiguous"


def test_bounce_and_unsafe_reply_messages_never_call_classifier():
    for headers in (
        {"From": "mailer-daemon@example.test"},
        {"Reply-To": "one@example.test, two@example.test"},
    ):
        email = message_to_email(_message("Class of 2027", headers=headers))
        email["message_id"] = "m1"
        calls = []
        plan = plan_message(
            email, {"administrative": "approved"}, {}, {}, True,
            classifier=lambda _email: calls.append(_email),
        )
        assert calls == []
        assert plan["template"] is None
        assert "YEAR_LABEL" not in plan["decision"].add


def test_year_label_requires_local_evidence_high_confidence_and_recruit_sender():
    def plan(body, result):
        email = message_to_email(_message(body))
        email["message_id"] = "m1"
        return plan_message(
            email, {"recruit_intro_2027": "approved"},
            {"2027": "YEAR_LABEL"}, {"recruit_intro": "Intro", "parent": "Parent"},
            False, classifier=lambda _email: result,
            template_approvals=TemplateApprovals(
                name_only={"recruit_intro_2027"}
            ),
        )

    verified = plan("I am in the Class of 2027.", _result())
    assert set(verified["decision"].add) == {"Intro", "YEAR_LABEL"}
    assert verified["template"] == "approved"

    unrelated = plan("The schedule ends in 2027.", _result())
    assert "YEAR_LABEL" not in unrelated["decision"].add
    assert unrelated["template"] is None

    for confidence in ("low", "medium"):
        uncertain = plan("Class of 2027.", _result(confidence=confidence))
        assert uncertain["decision"].add == []
        assert uncertain["template"] is None

    parent = plan(
        "My son is a Class of 2027 recruit.",
        _result(category="parent", sender="parent"),
    )
    assert parent["decision"].add == ["Parent"]
    assert "YEAR_LABEL" not in parent["decision"].add

    coach = plan(
        "I coach a Class of 2027 recruit.",
        _result(category="other_coach", sender="coach"),
    )
    assert "YEAR_LABEL" not in coach["decision"].add


def test_model_and_local_year_disagreement_blocks_year_and_draft():
    email = message_to_email(_message("I am in the Class of 2028."))
    email["message_id"] = "m1"
    plan = plan_message(
        email, {"recruit_intro_2027": "approved"}, {"2027": "YEAR_LABEL"},
        {"recruit_intro": "Intro"}, False,
        classifier=lambda _email: _result(year="2027"),
    )
    assert "YEAR_LABEL" not in plan["decision"].add
    assert plan["template"] is None
    assert plan["year_evidence_conflict"] is True


def test_bounce_senders_never_draft_or_receive_a_year_label():
    """A bounce must be suppressed before classification, so it can receive
    neither a drafted reply nor the YEAR_LABEL label - even when its body would
    otherwise read as a confident 2027 recruit introduction."""
    from triage import TemplateApprovals, plan_message

    templates = {"recruit_intro": "Real reviewed wording."}
    approvals = TemplateApprovals(name_only={"recruit_intro"})

    def plan(sender):
        email = {
            "message_id": "m1", "from": sender, "subject": "Delivery Status",
            "body": "I am in the Class of 2027 and want to join the program.",
            "thread_id": "t1", "rfc_message_id": "<m1@mail>", "label_names": [],
        }
        return plan_message(
            email, templates, {"2027": "YEAR_LABEL"}, {"recruit_intro": "Intro"},
            no_label=False,
            classifier=lambda _e: {
                "category": "recruit_intro", "grad_year": "2027",
                "sender_type": "recruit", "confidence": "high",
            },
            template_approvals=approvals,
        )

    for sender in ("bounce@example.test", "bounces@example.test",
                   "bounce-9-x@example.test", "MAILER-DAEMON@example.test",
                   "postmaster@example.test"):
        result = plan(sender)
        assert result["suppression_code"] == "automated_message", sender
        assert result["classification_called"] is False, (
            f"{sender} was sent to the classifier despite being automated"
        )
        assert result["template"] is None, f"{sender} produced a draft"
        assert "YEAR_LABEL" not in result["decision"].add, (
            f"{sender} received the YEAR_LABEL recruit label"
        )

    # Control: a real recruit with the same body must still draft and label,
    # so the assertions above cannot pass because drafting is broken.
    control = plan("recruit@example.test")
    assert control["template"] is not None
    assert "YEAR_LABEL" in control["decision"].add


def test_bouncer_is_not_mistaken_for_a_bounce_address():
    """Guard against the bounce pattern over-matching a human address."""
    from message_safety import assess_delivery_headers

    assert assess_delivery_headers(
        {"from": "bouncer@example.test"}, own_address="c@example.edu"
    )["status"] == "normal"
