"""Privacy-safe local macOS failure notifications for scheduled triage."""
from __future__ import annotations

import logging
import subprocess


APP_TITLE = "Email Triage"
SAFE_COUNT_KEYS = (
    "scanned", "classified", "labeled", "drafted", "needs_review",
    "skipped", "failures", "deferred_draft_limit", "deferred_write_limit",
)
SAFE_ERROR_CODES = frozenset({
    "configuration_or_state_invalid",
    "draft_write_failed",
    "existing_manual_draft",
    "label_write_failed",
    "lock_already_held",
    "message_fetch_failed",
    "metadata_fetch_failed",
    "operator_aborted",
    "processed_label_failed",
    "required_labels_missing",
    "review_report_failed",
    "unexpected_message_failure",
    "unexpected_run_failure",
})
logger = logging.getLogger(__name__)


def _safe_nonnegative_int(value, default=0):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, number)


def safe_status_summary(status_document):
    """Extract only allowlisted counts and codes from a status document."""
    document = status_document if isinstance(status_document, dict) else {}
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}
    raw_counts = run.get("counts")
    raw_counts = raw_counts if isinstance(raw_counts, dict) else {}
    counts = {
        key: _safe_nonnegative_int(raw_counts.get(key, 0))
        for key in SAFE_COUNT_KEYS
    }
    raw_codes = run.get("safe_error_codes")
    raw_codes = raw_codes if isinstance(raw_codes, list) else []
    codes = sorted({
        code for code in raw_codes
        if isinstance(code, str) and code in SAFE_ERROR_CODES
    })
    return counts, codes


def build_failure_message(exit_code, status_document=None):
    """Build a fixed-vocabulary notification with no mailbox data."""
    code = _safe_nonnegative_int(exit_code, default=1)
    counts, error_codes = safe_status_summary(status_document)
    parts = [
        f"Email triage failed (exit {code}).",
        f"scanned={counts['scanned']}",
        f"drafted={counts['drafted']}",
        f"failures={counts['failures']}.",
    ]
    if error_codes:
        parts.append("Codes: " + ", ".join(error_codes) + ".")
    parts.append("Check the private status file.")
    return " ".join(parts)


def notify_failure(exit_code, status_document=None, runner=None):
    """Show one local notification; return False if the OS call fails."""
    message = build_failure_message(exit_code, status_document)
    # Both strings contain only fixed text, integers, and allowlisted codes.
    script = (
        'display notification "' + message + '" with title "' + APP_TITLE + '"'
    )
    run = runner or subprocess.run
    try:
        result = run(
            ["/usr/bin/osascript", "-e", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        logger.warning("Local failure notification could not be displayed")
        return False
    if result.returncode != 0:
        logger.warning("Local failure notification could not be displayed")
        return False
    return True
