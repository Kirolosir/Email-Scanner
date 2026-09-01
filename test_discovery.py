"""Offline tests for taxonomy discovery: sampling, redaction, proposal
parsing, and the review file.

Discovery is the most data-exposing step in the tool, so the properties under
test are mostly about restraint: what leaves the mailbox, what reaches the
model, and what the output is allowed to authorize (nothing).

Gmail and Gemini are both faked. No test here contacts either.
"""
import json
import os

import pytest

import discover_taxonomy
import discovery
from discovery import (
    DEFAULT_SAMPLE,
    MAX_SAMPLE,
    MAX_SUBJECT_CHARS,
    build_review_document,
    parse_proposals,
    propose_taxonomy,
    redact_subject,
    render_sample,
    sample_inbox,
    write_review_file,
)
from gmail_common import QuotaThrottle
from taxonomy import TaxonomyError, load_taxonomy_confirmation

ACCOUNT = "owner@example.test"

MODEL_REPLY = json.dumps({"categories": [
    {"name": "Recruiting", "description": "Prospective players",
     "examples": ["Class of 2027 midfielder"]},
    {"name": "Marketing", "description": "Vendor and promo mail",
     "examples": ["50% off team gear"]},
]})


class _FakeCall:
    def __init__(self, result):
        self._result = result

    def execute(self):
        return self._result


class _FakeGmail:
    """Records every call so the test can assert what discovery asked for."""

    def __init__(self, messages):
        self._messages = messages
        self.get_calls = []
        self.list_calls = []
        self.other_calls = []

    def users(self):
        return self

    def messages(self):
        return self

    def labels(self):
        return self

    def drafts(self):
        return self

    def list(self, userId, **kwargs):
        self.list_calls.append(kwargs)
        return _FakeCall({"messages": [{"id": m["id"]} for m in self._messages]})

    def get(self, userId, id, format=None, metadataHeaders=None):
        self.get_calls.append({"id": id, "format": format,
                               "metadataHeaders": metadataHeaders})
        record = next(m for m in self._messages if m["id"] == id)
        return _FakeCall({
            "id": id,
            "payload": {"headers": [
                {"name": "Subject", "value": record["subject"]},
                {"name": "From", "value": record["from"]},
            ]},
        })

    # Any write would be a bug; record rather than perform.
    def create(self, *a, **k):
        self.other_calls.append("create")
        return _FakeCall({})

    def modify(self, *a, **k):
        self.other_calls.append("modify")
        return _FakeCall({})


def _messages(count=3):
    return [
        {"id": f"m{i}", "subject": f"Subject number {i}",
         "from": "person@example.test"}
        for i in range(count)
    ]


def _throttle():
    return QuotaThrottle(units_per_second=100_000)


# --------------------------------------------------------------------
# What leaves the mailbox
# --------------------------------------------------------------------

def test_sampling_requests_metadata_only_never_bodies():
    """Bodies are never fetched, so they cannot be sent anywhere."""
    service = _FakeGmail(_messages())
    sample_inbox(service, "in:inbox", _throttle(), own_address=ACCOUNT)

    assert service.get_calls, "expected discovery to fetch message metadata"
    for call in service.get_calls:
        assert call["format"] == "metadata", (
            "discovery fetched a full message; bodies must never be read"
        )
        # Bulk detection needs these; fetching only Subject/From left it
        # blind and mislabelled marketing mail as person-sent.
        assert set(call["metadataHeaders"]) >= {
            "Subject", "From", "List-Unsubscribe", "Precedence",
            "Auto-Submitted", "X-Auto-Response-Suppress",
        }


def test_sampling_performs_no_gmail_writes():
    service = _FakeGmail(_messages())
    sample_inbox(service, "in:inbox", _throttle(), own_address=ACCOUNT)

    assert service.other_calls == [], (
        f"discovery attempted Gmail writes: {service.other_calls}"
    )


def test_sample_never_carries_the_real_message_id():
    service = _FakeGmail(_messages())
    samples = sample_inbox(service, "in:inbox", _throttle(),
                           own_address=ACCOUNT)

    real_ids = {m["id"] for m in _messages()}
    for entry in samples:
        assert entry["id"] not in real_ids, "raw Gmail id leaked into the sample"


@pytest.mark.parametrize("requested,expected", [
    (10, 10), (0, 1), (-5, 1), (MAX_SAMPLE + 500, MAX_SAMPLE),
])
def test_sample_size_is_clamped(requested, expected):
    """An uncapped scan is both a quota and a data-exposure problem."""
    service = _FakeGmail(_messages(count=MAX_SAMPLE + 600))
    samples = sample_inbox(service, "in:inbox", _throttle(),
                           max_messages=requested, own_address=ACCOUNT)

    assert len(samples) == expected
    assert service.list_calls[0]["maxResults"] == expected


# --------------------------------------------------------------------
# What reaches the model
# --------------------------------------------------------------------

@pytest.mark.parametrize("subject,expected", [
    ("Re: from nick@example.com about camp", "Re: from [address] about camp"),
    ("plain subject", "plain subject"),
    ("  padded   spaces  ", "padded spaces"),
    ("", ""),
    (None, ""),
])
def test_subjects_are_redacted_before_leaving(subject, expected):
    assert redact_subject(subject) == expected


def test_long_subjects_are_truncated():
    assert len(redact_subject("x" * 5000)) == MAX_SUBJECT_CHARS


def test_prompt_contains_only_redacted_subjects_and_a_sender_tag():
    """The exact payload sent to Gemini must carry no address and no body."""
    service = _FakeGmail([
        {"id": "m1", "subject": "Ping from kid@school.edu",
         "from": "kid@school.edu"},
        {"id": "m2", "subject": "Sale ends today",
         "from": "no-reply@vendor.test"},
    ])
    samples = sample_inbox(service, "in:inbox", _throttle(),
                           own_address=ACCOUNT)

    captured = {}

    def fake_model(prompt):
        captured["prompt"] = prompt
        return MODEL_REPLY

    propose_taxonomy(samples, model_fn=fake_model)
    prompt = captured["prompt"]

    assert "kid@school.edu" not in prompt
    assert "no-reply@vendor.test" not in prompt
    assert "[address]" in prompt
    assert "[automated]" in prompt and "[person]" in prompt
    assert "Sale ends today" in prompt


def test_render_sample_marks_automated_senders():
    text = render_sample([
        {"subject": "a", "automated": True, "id": "x"},
        {"subject": "b", "automated": False, "id": "y"},
    ])
    assert "[automated] a" in text and "[person] b" in text


# --------------------------------------------------------------------
# Model output is untrusted
# --------------------------------------------------------------------

def test_proposals_pass_through_sanitization():
    """A hostile or sloppy name must be normalized, never used raw."""
    reply = json.dumps({"categories": [
        {"name": "  School / Admin!!  ", "description": "d", "examples": []},
    ]})
    taxonomy = propose_taxonomy(
        [{"subject": "s", "automated": False, "id": "i"}],
        model_fn=lambda _p: reply,
    )

    assert taxonomy[0]["slug"] == "school_admin"
    assert taxonomy[0]["digest"].startswith("sha256:")


@pytest.mark.parametrize("hostile_label", [
    "INBOX", "TRASH", "Triage/Taken", "../escape", "a\nb", "x" * 400,
])
def test_model_cannot_name_a_gmail_label(hostile_label):
    """Stronger than validating a model-proposed label: the model has no
    path to naming one at all. parse_proposals carries forward only
    name/description/examples, so a "label" key in the reply is dropped.

    Discovery originally relied on that by omission, which would have broken
    silently the first time someone added label passthrough. It is now
    explicit in the code and pinned here."""
    reply = json.dumps({"categories": [
        {"name": "ok", "label": hostile_label, "description": "d",
         "examples": []},
    ]})

    parsed = parse_proposals(reply)
    assert parsed and "label" not in parsed[0], (
        "a model-supplied label reached the taxonomy builder"
    )

    taxonomy = propose_taxonomy(
        [{"subject": "s", "automated": False, "id": "i"}],
        model_fn=lambda _p: reply,
        existing_labels=["Triage/Taken"],
    )
    assert taxonomy[0].get("label") is None
    assert taxonomy[0]["slug"] == "ok"


def test_label_validation_still_applies_when_a_label_is_supplied():
    """The builder's label checks remain live for the paths that do supply
    one (account configs, migration), so dropping the model's label is not
    the only thing standing between a bad name and Gmail."""
    from taxonomy import build_taxonomy

    with pytest.raises(TaxonomyError):
        build_taxonomy([{"name": "ok", "label": "INBOX"}])
    with pytest.raises(TaxonomyError, match="already exists"):
        build_taxonomy([{"name": "ok", "label": "Triage/Taken"}],
                       existing_labels=["Triage/Taken"])


@pytest.mark.parametrize("reply", [
    "", "not json", "[]", "{}", '{"categories": "nope"}',
    '{"categories": []}', '{"categories": [{"no_name": 1}]}',
    '{"categories": [{"name": "   "}]}', None,
])
def test_unusable_model_replies_raise_rather_than_proposing_junk(reply):
    with pytest.raises(ValueError, match="no usable categories"):
        propose_taxonomy([{"subject": "s", "automated": False, "id": "i"}],
                         model_fn=lambda _p: reply)


def test_fenced_json_reply_is_accepted():
    fenced = f"```json\n{MODEL_REPLY}\n```"
    assert len(parse_proposals(fenced)) == 2


def test_proposal_count_is_capped():
    many = json.dumps({"categories": [
        {"name": f"cat{i}", "description": "", "examples": []}
        for i in range(50)
    ]})
    assert len(parse_proposals(many)) == discovery.MAX_PROPOSED_CATEGORIES


def test_discovery_refuses_an_empty_sample():
    with pytest.raises(ValueError, match="at least one sampled message"):
        propose_taxonomy([], model_fn=lambda _p: MODEL_REPLY)


# --------------------------------------------------------------------
# The review file grants nothing
# --------------------------------------------------------------------

def _document():
    taxonomy = propose_taxonomy(
        [{"subject": "s", "automated": False, "id": "i"}],
        model_fn=lambda _p: MODEL_REPLY,
    )
    return build_review_document(ACCOUNT, taxonomy, 42), taxonomy


def test_review_file_is_not_a_confirmation_artifact(tmp_path):
    """The critical property: discovery must never produce something that
    could be mistaken for, or loaded as, an owner's approval."""
    document, _ = _document()
    path = str(tmp_path / "review.json")
    write_review_file(document, path)

    assert document["status"] == "proposed"
    assert "confirmed_categories" not in document

    with pytest.raises(TaxonomyError):
        load_taxonomy_confirmation(path, ACCOUNT)


def test_review_document_says_drafting_stays_blocked():
    document, _ = _document()
    assert "proposals, not approvals" in document["note"]
    assert "blocked" in document["note"]


def test_review_file_is_owner_only(tmp_path):
    document, _ = _document()
    path = str(tmp_path / "nested" / "review.json")
    write_review_file(document, path)

    assert oct(os.stat(path).st_mode)[-3:] == "600"
    assert oct(os.stat(os.path.dirname(path)).st_mode)[-3:] == "700"


def test_review_file_is_never_overwritten(tmp_path):
    document, _ = _document()
    path = tmp_path / "review.json"
    path.write_text('{"existing": true}')

    with pytest.raises(FileExistsError, match="never overwrites"):
        write_review_file(document, str(path))
    assert json.loads(path.read_text()) == {"existing": True}


def test_review_text_lists_categories_and_examples():
    document, taxonomy = _document()
    text = discovery.review_text(document, taxonomy)

    assert "Sampled 42 messages" in text
    assert "recruiting" in text and "marketing" in text
    assert "Drafting stays blocked" in text


# --------------------------------------------------------------------
# CLI refuses to reach out without an explicit acknowledgement
# --------------------------------------------------------------------

def test_cli_refuses_to_contact_anything_without_live(capsys, tmp_path):
    code = discover_taxonomy.main([
        "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
    ])
    assert code == 2
    assert "Refusing to contact" in capsys.readouterr().out
    assert not (tmp_path / "r.json").exists()


def test_cli_defaults_are_conservative():
    args = discover_taxonomy.parse_args(
        ["--account", ACCOUNT, "--output", "r.json"]
    )
    assert args.live is False
    assert args.max_sample == DEFAULT_SAMPLE
    assert "newer_than:2m" in args.query
    assert "in:inbox" not in args.query
    assert "-in:sent" in args.query and "-in:trash" in args.query


def test_discovery_never_imports_a_write_capable_path():
    """Static check: the discovery module reads and proposes only."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("discovery.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    for forbidden in ("gmail_labeler", "setup_labels", "campaign", "drafting"):
        assert forbidden not in imported, (
            f"discovery.py imports {forbidden}; discovery must not be able "
            "to label, draft, or campaign"
        )


# --------------------------------------------------------------------
# Flag semantics. --live and --dry-run control different things, and the
# distinction was previously undocumented and easy to get wrong: a command
# described as "offline" still called Gemini.
# --------------------------------------------------------------------

def _samples_file(tmp_path):
    path = tmp_path / "samples.json"
    path.write_text(json.dumps([
        {"subject": "Class of 2027 midfielder", "automated": False, "id": "a"},
        {"subject": "50% off team gear", "automated": True, "id": "b"},
    ]))
    return str(path)


def _no_network(monkeypatch):
    """Make any model call an immediate, loud failure."""
    def explode(*a, **k):
        raise AssertionError("a Gemini call was made")
    monkeypatch.setattr(discovery, "_call_model", explode)
    monkeypatch.setattr(discovery.gemini_client, "generate_text", explode)


def test_show_prompt_with_a_local_sample_makes_no_model_call(
    tmp_path, monkeypatch, capsys
):
    """The genuinely offline path: no --live, no network, and the operator
    sees exactly what would be sent."""
    _no_network(monkeypatch)

    code = discover_taxonomy.main([
        "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
        "--samples-file", _samples_file(tmp_path), "--show-prompt",
    ])
    out = capsys.readouterr().out

    assert code == 0
    assert "No model call was made" in out
    assert "Class of 2027 midfielder" in out
    assert not (tmp_path / "r.json").exists()


def test_previewed_prompt_is_the_prompt_that_would_be_sent(monkeypatch):
    """A separate rendering could drift from the real payload, so the
    preview and the send must come from one function."""
    samples = [{"subject": "s", "automated": False, "id": "i"}]
    captured = {}

    def capture(prompt):
        captured["prompt"] = prompt
        return MODEL_REPLY

    propose_taxonomy(samples, model_fn=capture)
    assert captured["prompt"] == discovery.build_prompt(samples)


def test_samples_file_without_show_prompt_still_requires_live(
    tmp_path, monkeypatch, capsys
):
    """A local sample does not by itself authorize a model call."""
    _no_network(monkeypatch)

    code = discover_taxonomy.main([
        "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
        "--samples-file", _samples_file(tmp_path),
    ])
    assert code == 2
    assert "Refusing to contact" in capsys.readouterr().out


def test_show_prompt_without_a_sample_file_still_requires_live(
    tmp_path, monkeypatch, capsys
):
    """--show-prompt alone cannot read the mailbox to build a sample."""
    _no_network(monkeypatch)

    code = discover_taxonomy.main([
        "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
        "--show-prompt",
    ])
    assert code == 2
    assert "Refusing to contact" in capsys.readouterr().out


def test_dry_run_does_not_gate_the_model_call(tmp_path):
    """The distinction that made the earlier instructions wrong: --dry-run
    skips only the review-file write. It is NOT a network guard."""
    calls = []

    def counting_model(prompt):
        calls.append(prompt)
        return MODEL_REPLY

    import unittest.mock as mock
    with mock.patch.object(discovery, "_call_model", counting_model):
        code = discover_taxonomy.main([
            "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
            "--samples-file", _samples_file(tmp_path), "--live", "--dry-run",
        ])

    assert code == 0
    assert len(calls) == 1, (
        "--dry-run must not be mistaken for a network guard; it skips only "
        "the file write"
    )
    assert not (tmp_path / "r.json").exists(), "--dry-run wrote a review file"


def test_help_text_states_what_each_flag_controls():
    """The flags are only safe if their scope is stated where it is read."""
    import argparse
    import io
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        with pytest.raises(SystemExit):
            discover_taxonomy.parse_args(["--help"])
    text = buffer.getvalue()

    assert "ANY network call" in text
    assert "Does NOT prevent" in text
    assert "makes no model call" in text.lower()


def test_cli_preview_prints_the_whole_prompt_not_just_the_sample(
    tmp_path, monkeypatch, capsys
):
    """The drift that actually matters: the CLI could print something
    shorter than what it would send (the sample without the instructions),
    and the operator would approve a payload they never saw in full."""
    _no_network(monkeypatch)

    samples_path = _samples_file(tmp_path)
    with open(samples_path, encoding="utf-8") as handle:
        samples = json.load(handle)

    discover_taxonomy.main([
        "--account", ACCOUNT, "--output", str(tmp_path / "r.json"),
        "--samples-file", samples_path, "--show-prompt",
    ])
    out = capsys.readouterr().out

    expected = discovery.build_prompt(samples)
    assert expected in out, (
        "the preview did not print the exact prompt that would be sent"
    )
    # And the instruction text, not merely the subject lines.
    assert "Respond as strict JSON" in out
    assert "Do not invent categories" in out


def test_output_is_not_required_for_a_preview(tmp_path, monkeypatch, capsys):
    """--show-prompt writes nothing, so demanding an output path invited
    pointing it at a real one for no reason."""
    _no_network(monkeypatch)

    code = discover_taxonomy.main([
        "--account", ACCOUNT,
        "--samples-file", _samples_file(tmp_path), "--show-prompt",
    ])
    assert code == 0
    assert "No model call was made" in capsys.readouterr().out


def test_output_is_still_required_for_a_writing_run(tmp_path, capsys):
    code = discover_taxonomy.main([
        "--account", ACCOUNT,
        "--samples-file", _samples_file(tmp_path), "--live",
    ])
    assert code == 2
    assert "--output is required" in capsys.readouterr().out


def test_bulk_mail_is_detected_from_headers_not_just_the_sender():
    """Regression for a bug only a live run surfaced: marketing blasts were
    tagged [person] because the bulk headers were never fetched."""
    service = _FakeGmail([{
        "id": "m1", "subject": "Labor Day Sale", "from": "news@shop.test",
    }])
    # Give the fake the bulk header the real API would return.
    original_get = service.get

    def get_with_bulk(userId, id, format=None, metadataHeaders=None):
        call = original_get(userId, id, format=format,
                            metadataHeaders=metadataHeaders)
        call._result["payload"]["headers"].append(
            {"name": "List-Unsubscribe", "value": "<mailto:u@shop.test>"}
        )
        return call

    service.get = get_with_bulk
    samples = sample_inbox(service, "in:inbox", _throttle(),
                           own_address=ACCOUNT)

    assert samples[0]["automated"] is True, (
        "a List-Unsubscribe blast was tagged as person-sent"
    )


def test_bulk_headers_are_used_locally_and_never_sent():
    """The extra headers improve local classification only. Their contents
    must not reach the model payload."""
    service = _FakeGmail([{
        "id": "m1", "subject": "Sale", "from": "news@shop.test",
    }])
    original_get = service.get

    def get_with_bulk(userId, id, format=None, metadataHeaders=None):
        call = original_get(userId, id, format=format,
                            metadataHeaders=metadataHeaders)
        call._result["payload"]["headers"].append(
            {"name": "List-Unsubscribe", "value": "<mailto:secret@shop.test>"}
        )
        return call

    service.get = get_with_bulk
    samples = sample_inbox(service, "in:inbox", _throttle(),
                           own_address=ACCOUNT)
    prompt = discovery.build_prompt(samples)

    assert "secret@shop.test" not in prompt
    assert "List-Unsubscribe" not in prompt
    assert "[automated] Sale" in prompt
