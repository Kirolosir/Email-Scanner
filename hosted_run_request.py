"""Private handoff from the dashboard to the short-lived hosted runner.

The dashboard cannot decrypt Gmail credentials and cannot start operating-system
services. It can only write this small, account-bound request. A systemd path
unit notices the file and starts the already-sandboxed runner.
"""
from __future__ import annotations

import datetime as dt
import hmac
import json
import os
from pathlib import Path

import connection
from message_safety import opaque_id
from private_runtime import atomic_write_json


REQUEST_FILE = "run-now-request.json"
REQUEST_VERSION = 2
MAX_REQUEST_AGE = dt.timedelta(hours=1)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)
MAX_HISTORY_MESSAGES = 250
REQUIRED_SETUP_FILES = (
    "account.json",
    "taxonomy-confirmation.json",
    "ai-drafting-approval.json",
)


class RunRequestError(RuntimeError):
    """A safe, message-free reason an immediate run could not be requested."""


def _utc_now(value=None):
    value = value or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise RunRequestError("the request clock must include a timezone")
    return value.astimezone(dt.timezone.utc)


def _account_hash(account):
    return opaque_id(connection.normalize_account(account), 16)


def request_path(active):
    return Path(active) / REQUEST_FILE


def _history_count(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RunRequestError("the history count must be a whole number")
    if not 1 <= value <= MAX_HISTORY_MESSAGES:
        raise RunRequestError(
            f"the history count must be between 1 and {MAX_HISTORY_MESSAGES}"
        )
    return value


def request_run(root, *, now=None, history_count=None):
    """Queue one bounded recent or historical run after setup is complete."""
    root = Path(root)
    requested_at = _utc_now(now)
    history_count = _history_count(history_count)
    with connection.lifecycle_lock(root):
        occupant = connection.current(root)
        if occupant is None:
            raise RunRequestError("link a Google account before running")
        if not occupant.enabled:
            raise RunRequestError("the connected account is not enabled")
        active = Path(occupant.directory)
        if any(not (active / name).is_file() for name in REQUIRED_SETUP_FILES):
            raise RunRequestError("save labels and schedule before running")
        atomic_write_json(request_path(active), {
            "version": REQUEST_VERSION,
            "account_hash": _account_hash(occupant.account),
            "requested_at": requested_at.isoformat(timespec="seconds"),
            "scope": "history" if history_count is not None else "recent",
            "message_count": history_count,
        })
        return int(requested_at.timestamp())


def load_request(active, occupant, *, now=None):
    """Return a strictly validated request, or None when no request exists."""
    path = request_path(active)
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise RunRequestError("the immediate-run request is unreadable") from exc

    if not isinstance(document, dict):
        raise RunRequestError("the immediate-run request must be an object")
    if set(document) != {
        "version", "account_hash", "requested_at", "scope", "message_count",
    }:
        raise RunRequestError("the immediate-run request has unsupported fields")
    if document.get("version") != REQUEST_VERSION:
        raise RunRequestError("the immediate-run request version is unsupported")
    scope = document.get("scope")
    if scope not in {"recent", "history"}:
        raise RunRequestError("the immediate-run request scope is unsupported")
    message_count = _history_count(document.get("message_count"))
    if (scope == "history") != (message_count is not None):
        raise RunRequestError("the immediate-run request scope is inconsistent")
    account_hash = document.get("account_hash")
    if not isinstance(account_hash, str) or not hmac.compare_digest(
            account_hash, _account_hash(occupant.account)):
        raise RunRequestError("the immediate-run request belongs to another account")

    raw_stamp = document.get("requested_at")
    if not isinstance(raw_stamp, str):
        raise RunRequestError("the immediate-run request has no valid timestamp")
    try:
        requested_at = dt.datetime.fromisoformat(raw_stamp)
    except ValueError as exc:
        raise RunRequestError("the immediate-run request has no valid timestamp") from exc
    if requested_at.tzinfo is None or requested_at.utcoffset() is None:
        raise RunRequestError("the immediate-run request timestamp has no timezone")
    requested_at = requested_at.astimezone(dt.timezone.utc)
    current = _utc_now(now)
    if requested_at > current + MAX_CLOCK_SKEW:
        raise RunRequestError("the immediate-run request timestamp is in the future")
    if current - requested_at > MAX_REQUEST_AGE:
        raise RunRequestError("the immediate-run request has expired")
    return document


def consume_request(active, occupant, *, now=None):
    """Validate and remove one request before any mailbox access begins."""
    document = load_request(active, occupant, now=now)
    if document is None:
        return None
    try:
        os.unlink(request_path(active))
    except OSError as exc:
        raise RunRequestError("the immediate-run request could not be consumed") from exc
    return document


def discard_request(active):
    """Remove a malformed request so it cannot create an activation loop."""
    try:
        os.unlink(request_path(active))
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RunRequestError("the immediate-run request could not be discarded") from exc
