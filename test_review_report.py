"""Offline privacy and durability tests for triage review reports."""
import ast
import json
import os
from pathlib import Path

import pytest

import daily_triage
import review_report
from gmail_labeler import LabelDecision
from review_report import (
    ReviewReportReservation,
    build_review_report,
    validate_review_report,
)


PRIVATE_MARKERS = (
    "PRIVATE SUBJECT MARKER",
    "person@example.test",
    "PRIVATE BODY MARKER",
    "raw-message-id-123",
    "PRIVATE DRAFT MARKER",
    "refresh-token-value",
    "exception detail marker",
)


def _plan(message_id="raw-message-id-123"):
    return {
        "email": {
            "message_id": message_id,
            "subject": PRIVATE_MARKERS[0],
            "from": PRIVATE_MARKERS[1],
            "body": PRIVATE_MARKERS[2],
        },
        "classification": {
            "category": "general_request", "confidence": "high",
            "valid": True, "evidence": PRIVATE_MARKERS[2],
            "reason": PRIVATE_MARKERS[-1],
        },
        "category": "general_request",
        "confidence": "high",
        "decision": LabelDecision(add=["Triage/General"]),
        "template": PRIVATE_MARKERS[4],
        "processed_label": "Triage/Processed",
        "draft_source": "ai",
        "classification_called": True,
        "draft_skip": None,
        "suppression_code": "",
        "classification_error": None,
        "draft_generation_error": None,
        "year_evidence_conflict": False,
    }


def _document(plan=None, **overrides):
    values = {
        "mode": "initial", "applied": False, "outcome": "success",
        "deferred_reasons": {},
    }
    values.update(overrides)
    return build_review_report(
        [plan or _plan()], {"scanned": 1, "classified": 1}, **values
    )


def _mode(path):
    return os.stat(path).st_mode & 0o777


def test_report_contains_decisions_but_no_message_content_or_raw_ids():
    text = json.dumps(_document(), sort_keys=True)

    assert "general_request" in text
    assert "Triage/General" in text
    assert "opaque_message_id" in text
    for marker in PRIVATE_MARKERS:
        assert marker not in text


def test_report_marks_draft_and_write_deferrals_with_safe_codes():
    draft_plan = _plan("draft-limited")
    write_plan = _plan("write-limited")
    report = build_review_report(
        [draft_plan, write_plan],
        {"deferred_draft_limit": 1, "deferred_write_limit": 1},
        mode="daily", applied=False, outcome="success",
        deferred_reasons={
            id(draft_plan): "draft_limit_reached",
            id(write_plan): "write_limit_reached",
        },
    )

    assert report["messages"][0]["draft_planned"] is False
    assert report["messages"][0]["reason_codes"] == ["draft_limit_reached"]
    assert report["messages"][1]["reason_codes"] == ["write_limit_reached"]


def test_report_publish_is_private_atomic_and_never_overwrites(tmp_path):
    path = tmp_path / "private" / "review.json"
    writer = ReviewReportReservation(path).reserve()

    assert writer.marker_path.exists()
    assert _mode(path.parent) == 0o700
    assert _mode(writer.marker_path) == 0o600
    writer.finalize(_document())

    assert path.exists()
    assert _mode(path) == 0o600
    assert not writer.marker_path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1
    with pytest.raises(FileExistsError):
        ReviewReportReservation(path).reserve()


def test_interrupted_publish_leaves_clearly_named_valid_marker(
        monkeypatch, tmp_path):
    path = tmp_path / "review.json"
    writer = ReviewReportReservation(path).reserve()
    monkeypatch.setattr(
        review_report.os, "link",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic interruption")),
    )

    with pytest.raises(OSError):
        writer.finalize(_document())

    assert not path.exists()
    assert ".in-progress" in writer.marker_path.name
    marker = json.loads(writer.marker_path.read_text(encoding="utf-8"))
    assert marker["status"] == "in_progress"
    assert _mode(writer.marker_path) == 0o600


def test_schema_rejects_extra_fields_and_unsafe_reason_codes():
    report = _document()
    report["subject"] = "not allowed"
    with pytest.raises(ValueError, match="top-level"):
        validate_review_report(report)

    report = _document()
    report["messages"][0]["reason_codes"] = ["raw exception text"]
    with pytest.raises(ValueError, match="unsafe reason"):
        validate_review_report(report)


def test_writer_uses_exclusive_creation_in_each_sensitive_create_site():
    tree = ast.parse(Path("review_report.py").read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "open"
    ]
    assert len(calls) == 2
    for call in calls:
        flags = ast.unparse(call.args[1])
        assert "O_EXCL" in flags, f"sensitive create lost O_EXCL: {flags}"


@pytest.mark.parametrize("apply", [False, True])
def test_daily_cli_writes_report_for_dry_and_applied_runs(
        monkeypatch, tmp_path, apply):
    report_path = tmp_path / f"report-{apply}.json"

    def fake_run(args, classifier=None):
        plan = _plan()
        if apply:
            plan["_applied_labels"] = ["Triage/General", "Triage/Processed"]
            plan["new_draft_created"] = True
        args._review_context = {
            "plans": [plan],
            "counts": {"scanned": 1, "drafted": int(apply)},
            "deferred_reasons": {},
        }
        return 0

    monkeypatch.setattr(daily_triage, "_main_with_args", fake_run)
    argv = ["initial", "--review-report", str(report_path)]
    if apply:
        argv.append("--apply")
    result = daily_triage.main(argv)

    assert result == 0
    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["applied"] is apply
    assert document["messages"][0]["draft_created"] is apply
    for marker in PRIVATE_MARKERS:
        assert marker not in report_path.read_text(encoding="utf-8")


def test_existing_report_blocks_before_runtime_or_gmail(monkeypatch, tmp_path):
    path = tmp_path / "existing.json"
    path.write_text("{}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        daily_triage, "_main_with_args", lambda *_a, **_k: calls.append(True)
    )

    assert daily_triage.main(["initial", "--review-report", str(path)]) == 2
    assert calls == []
