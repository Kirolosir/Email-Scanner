"""Send a PII-free failure notice to a configured HTTPS webhook.

Payloads contain only allowlisted counts and error codes. Notification errors
return false instead of replacing the original run failure. Notifications use
a webhook because the application must never send mail.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse

from local_notifier import SAFE_COUNT_KEYS, SAFE_ERROR_CODES


PAYLOAD_VERSION = 1
TIMEOUT_SECONDS = 10

# An https endpoint only. A plaintext webhook would put the counts and codes
# on the wire in the clear, and more importantly would make it trivial to
# point this at something on the local network by mistake.
ALLOWED_SCHEMES = frozenset({"https"})

# Everything the payload may ever contain. Adding a field here is a reviewed
# decision, which is the point.
PAYLOAD_FIELDS = frozenset({
    "version", "seat", "outcome", "exit_code", "counts", "error_codes",
})


class NotifyConfigError(ValueError):
    """Raised at configuration time, never from the failure path."""


def validate_endpoint(url):
    """Check a webhook URL once, at startup, rather than at failure time."""
    if not isinstance(url, str) or not url.strip():
        raise NotifyConfigError("webhook endpoint must be a non-empty string")
    parsed = urlparse(url.strip())
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise NotifyConfigError("webhook endpoint must use https")
    if not parsed.netloc:
        raise NotifyConfigError("webhook endpoint has no host")
    return url.strip()


def _safe_int(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def build_payload(connection_id, exit_code, status_document=None):
    """Assemble the notice from allowlisted fields only.

    Mirrors local_notifier.safe_status_summary: unknown counts are dropped,
    unknown error codes are dropped, and anything malformed degrades to zero
    rather than passing through.
    """
    document = status_document if isinstance(status_document, dict) else {}
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}

    raw_counts = run.get("counts")
    raw_counts = raw_counts if isinstance(raw_counts, dict) else {}
    counts = {key: _safe_int(raw_counts.get(key, 0)) for key in SAFE_COUNT_KEYS}

    raw_codes = run.get("safe_error_codes")
    raw_codes = raw_codes if isinstance(raw_codes, list) else []
    codes = sorted({
        code for code in raw_codes
        if isinstance(code, str) and code in SAFE_ERROR_CODES
    })

    return {
        "version": PAYLOAD_VERSION,
        "seat": str(connection_id),
        "outcome": "failed",
        "exit_code": _safe_int(exit_code) or int(bool(exit_code)),
        "counts": counts,
        "error_codes": codes,
    }


def _default_sender(url, body):
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return 200 <= response.status < 300


def notify_failure(connection_id, endpoint, exit_code, status_document=None,
                   sender=None):
    """Post one failure notice. Returns True only on a confirmed delivery.

    Never raises. A notification that fails is a notification that fails; it
    must not become the error the operator ends up debugging instead of the
    one that actually happened.
    """
    try:
        url = validate_endpoint(endpoint)
    except NotifyConfigError:
        return False

    payload = build_payload(connection_id, exit_code, status_document)
    # Belt and braces: the payload is assembled from an allowlist above, and
    # checked against it again here, so a future edit to build_payload cannot
    # quietly widen what leaves the machine.
    if set(payload) != PAYLOAD_FIELDS:
        return False

    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    send = sender or _default_sender
    try:
        return bool(send(url, body))
    except (urllib.error.URLError, OSError, ValueError):
        return False
    except Exception:  # noqa: BLE001 - an injected sender may raise anything
        return False
