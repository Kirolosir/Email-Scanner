"""PII-minimized, crash-identifiable review reports for triage runs."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
from pathlib import Path

from message_safety import opaque_id
from private_runtime import ensure_private_directory
from triage_limits import requires_new_draft


REPORT_VERSION = 1
COUNT_KEYS = frozenset({
    "scanned", "classified", "labeled", "drafted", "needs_review",
    "skipped", "failures", "deferred_draft_limit", "deferred_write_limit",
})
REASON_CODES = frozenset({
    "automated_message",
    "classification_failed",
    "draft_generation_failed",
    "draft_limit_reached",
    "drafting_not_planned",
    "empty_cleaned_body",
    "existing_manual_draft",
    "invalid_classification",
    "label_conflict",
    "low_confidence",
    "message_execution_failed",
    "missing_owned_draft",
    "unsafe_reply_metadata",
    "safe_fallback_used",
    "write_limit_reached",
    "year_evidence_conflict",
})
_OPAQUE_ID = re.compile(r"^[0-9a-f]{16}$")


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _reason_codes(plan, deferred_reason=""):
    codes = set()
    if deferred_reason in REASON_CODES:
        codes.add(deferred_reason)
    suppression = plan.get("suppression_code")
    if suppression in REASON_CODES:
        codes.add(suppression)
    classification = plan.get("classification") or {}
    if plan.get("classification_error"):
        codes.add("classification_failed")
    if classification.get("valid") is False:
        codes.add("invalid_classification")
    if plan.get("confidence") not in {None, "high"}:
        codes.add("low_confidence")
    decision = plan.get("decision")
    if decision is not None and getattr(decision, "conflicts", None):
        codes.add("label_conflict")
    if plan.get("year_evidence_conflict"):
        codes.add("year_evidence_conflict")
    if plan.get("existing_manual_draft"):
        codes.add("existing_manual_draft")
    if plan.get("missing_owned_draft"):
        codes.add("missing_owned_draft")
    if plan.get("draft_generation_error"):
        codes.add("draft_generation_failed")
    if plan.get("draft_fallback_used"):
        codes.add("safe_fallback_used")
    if plan.get("_execution_error_codes"):
        codes.add("message_execution_failed")
    if plan.get("template") is None and plan.get("draft_skip"):
        codes.add("drafting_not_planned")
    return sorted(codes)


def _label_record(plan, applied):
    if applied and "_applied_labels" in plan:
        names = plan.get("_applied_labels") or []
        state = "applied"
    else:
        decision = plan.get("decision")
        names = list(getattr(decision, "add", ()) or ())
        processed = plan.get("processed_label")
        if processed:
            names.append(processed)
        state = "proposed"
    return {"state": state, "names": sorted(set(map(str, names)))}


def _drafting_mode(plan):
    source = plan.get("draft_source")
    if source == "ai":
        return "generic"
    if source == "template":
        return "template"
    if source == "fallback":
        return "fallback"
    return "off"


def _recruit_profile(plan):
    """Keep only bounded coach-review fields from the classifier result.

    These values are stored only in the private review artifact and rendered
    only inside the authenticated owner dashboard. They are never included in
    the public machine-status endpoint or service logs.
    """
    classification = plan.get("classification") or {}
    result = {}
    for source, target in (
        ("recruit_name", "name"),
        ("school", "school"),
        ("position", "position"),
        ("location", "location"),
        ("grad_year", "grad_year"),
        ("sender_type", "sender_type"),
    ):
        value = " ".join(str(classification.get(source) or "unknown").split())
        result[target] = value[:120] or "unknown"
    return result


def build_review_report(plans, counts, *, mode, applied, outcome,
                        deferred_reasons=None):
    """Build the versioned report from safe, locally derived fields only."""
    deferred_reasons = deferred_reasons or {}
    items = []
    for plan in plans:
        email = plan.get("email") or {}
        deferred_reason = deferred_reasons.get(id(plan), "")
        eligible = plan.get("template") is not None
        items.append({
            "opaque_message_id": opaque_id(email.get("message_id", ""), length=16),
            "category": str(plan.get("category") or "unknown"),
            "confidence": str(plan.get("confidence") or "unknown"),
            "labels": _label_record(plan, applied),
            "draft_eligible": bool(eligible),
            "draft_planned": bool(
                eligible and not deferred_reason and requires_new_draft(plan)
            ),
            "draft_created": bool(plan.get("new_draft_created", False)),
            "drafting_mode": _drafting_mode(plan),
            "recruit_profile": _recruit_profile(plan),
            "reason_codes": _reason_codes(plan, deferred_reason),
            "classification_called": bool(plan.get("classification_called", False)),
        })
    safe_counts = {
        key: max(0, int(value))
        for key, value in (counts or {}).items()
        if key in COUNT_KEYS
    }
    document = {
        "version": REPORT_VERSION,
        "created_at": _now(),
        "run_mode": str(mode),
        "applied": bool(applied),
        "outcome": "success" if outcome == "success" else "failed",
        "counts": dict(sorted(safe_counts.items())),
        "messages": items,
    }
    validate_review_report(document)
    return document


def validate_review_report(document):
    """Reject schema drift before a report is written."""
    expected_top = {
        "version", "created_at", "run_mode", "applied", "outcome",
        "counts", "messages",
    }
    if not isinstance(document, dict) or set(document) != expected_top:
        raise ValueError("review report has unsupported top-level fields")
    if document.get("version") != REPORT_VERSION:
        raise ValueError("review report has an unsupported version")
    if document.get("outcome") not in {"success", "failed"}:
        raise ValueError("review report has an invalid outcome")
    counts = document.get("counts")
    if not isinstance(counts, dict) or set(counts) - COUNT_KEYS:
        raise ValueError("review report has unsupported count fields")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in counts.values()):
        raise ValueError("review report counts must be nonnegative integers")
    expected_item = {
        "opaque_message_id", "category", "confidence", "labels",
        "draft_eligible", "draft_planned", "draft_created", "drafting_mode",
        "reason_codes", "classification_called",
    }
    if not isinstance(document.get("messages"), list):
        raise ValueError("review report messages must be a list")
    for item in document["messages"]:
        if (not isinstance(item, dict)
                or not expected_item.issubset(item)
                or set(item) - (expected_item | {"recruit_profile"})):
            raise ValueError("review report message has unsupported fields")
        if not _OPAQUE_ID.fullmatch(item["opaque_message_id"]):
            raise ValueError("review report message identifier is not opaque")
        labels = item.get("labels")
        if (not isinstance(labels, dict) or set(labels) != {"state", "names"}
                or labels.get("state") not in {"proposed", "applied"}
                or not isinstance(labels.get("names"), list)
                or not all(isinstance(name, str) for name in labels["names"])):
            raise ValueError("review report labels are invalid")
        if set(item.get("reason_codes", ())) - REASON_CODES:
            raise ValueError("review report contains an unsafe reason code")
        recruit = item.get("recruit_profile")
        if recruit is not None:
            expected_recruit = {
                "name", "school", "position", "location", "grad_year",
                "sender_type",
            }
            if (not isinstance(recruit, dict)
                    or set(recruit) != expected_recruit
                    or not all(
                        isinstance(value, str) and 0 < len(value) <= 120
                        for value in recruit.values()
                    )):
                raise ValueError("review report has invalid recruit details")
    return document


class ReviewReportReservation:
    """Reserve a report path and publish complete JSON without overwriting."""

    def __init__(self, path):
        self.path = Path(path)
        self.marker_path = self.path.with_name(f".{self.path.name}.in-progress")
        self.finalized = False

    @staticmethod
    def _write_descriptor(descriptor, document):
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())

    def reserve(self):
        ensure_private_directory(self.path.parent)
        if self.path.exists():
            raise FileExistsError(f"review report already exists: {self.path}")
        descriptor = os.open(
            self.marker_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        self._write_descriptor(descriptor, {
            "version": REPORT_VERSION,
            "status": "in_progress",
            "started_at": _now(),
        })
        return self

    def finalize(self, document):
        validate_review_report(document)
        if self.finalized:
            raise RuntimeError("review report was already finalized")
        temporary = self.marker_path.with_name(
            f"{self.marker_path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        self._write_descriptor(descriptor, document)
        # A hard link publishes the fully written inode only if the target is
        # still absent. Unlike os.replace, it cannot overwrite a raced target.
        os.link(temporary, self.path)
        os.chmod(self.path, 0o600)
        os.unlink(temporary)
        os.unlink(self.marker_path)
        self.finalized = True
        return self.path
