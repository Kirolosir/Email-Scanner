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
from rollback_journal import GROUP_ID, latest_summary


REQUEST_FILE = "run-now-request.json"
CANCEL_FILE = "cancel-run-request.json"
BACKFILL_FILE = "backfill-job.json"
REQUEST_VERSION = 3
MAX_REQUEST_AGE = dt.timedelta(hours=1)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)
MAX_HISTORY_MESSAGES = 5000
REQUIRED_SETUP_FILES = (
    "account.json",
    "taxonomy-confirmation.json",
    "ai-drafting-approval.json",
)


class RunRequestError(RuntimeError):
    """A safe, message-free reason an immediate run could not be requested."""


class RunAlreadyActive(RunRequestError):
    """A queued or running mailbox job already owns the single connection."""


def _utc_now(value=None):
    value = value or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise RunRequestError("the request clock must include a timezone")
    return value.astimezone(dt.timezone.utc)


def _account_hash(account):
    return opaque_id(connection.normalize_account(account), 16)


def request_path(active):
    return Path(active) / REQUEST_FILE


def cancel_path(active):
    return Path(active) / CANCEL_FILE


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
    try:
        with connection.lifecycle_lock(root, blocking=False):
            occupant = connection.current(root)
            if occupant is None:
                raise RunRequestError("link a Google account before running")
            if not occupant.enabled:
                raise RunRequestError("the connected account is not enabled")
            active = Path(occupant.directory)
            if request_path(active).is_file():
                raise RunAlreadyActive("a mailbox run is already queued")
            if history_count is not None and (active / BACKFILL_FILE).is_file():
                raise RunAlreadyActive("a history backfill is already active")
            if any(not (active / name).is_file() for name in REQUIRED_SETUP_FILES):
                raise RunRequestError("save labels and schedule before running")
            atomic_write_json(request_path(active), {
                "version": REQUEST_VERSION,
                "account_hash": _account_hash(occupant.account),
                "requested_at": requested_at.isoformat(timespec="seconds"),
                "scope": "history" if history_count is not None else "recent",
                "message_count": history_count,
                "rollback_group": None,
            })
            return int(requested_at.timestamp())
    except connection.ConnectionBusy as exc:
        raise RunAlreadyActive("a mailbox run is already in progress") from exc


def request_cancel(root, *, now=None):
    """Request cooperative cancellation of the connected mailbox's live run."""
    root = Path(root)
    requested_at = _utc_now(now)
    occupant = connection.current(root)
    if occupant is None:
        raise RunRequestError("link a Google account before cancelling")
    status_path = Path(occupant.directory) / "daily-status.json"
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        status = {}
    run = status.get("last_run") if isinstance(status, dict) else None
    if not isinstance(run, dict) or run.get("outcome") != "running":
        raise RunRequestError("there is no running mailbox scan to cancel")
    atomic_write_json(cancel_path(occupant.directory), {
        "version": 1,
        "account_hash": _account_hash(occupant.account),
        "requested_at": requested_at.isoformat(timespec="seconds"),
    })
    return int(requested_at.timestamp())


def cancel_requested(active, occupant, *, now=None):
    """Return whether a fresh, account-bound cancellation request exists."""
    try:
        document = json.loads(cancel_path(active).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict) or set(document) != {
            "version", "account_hash", "requested_at"}:
        return False
    if document.get("version") != 1:
        return False
    account_hash = document.get("account_hash")
    if not isinstance(account_hash, str) or not hmac.compare_digest(
            account_hash, _account_hash(occupant.account)):
        return False
    raw_stamp = document.get("requested_at")
    if not isinstance(raw_stamp, str):
        return False
    try:
        requested_at = dt.datetime.fromisoformat(raw_stamp)
    except ValueError:
        return False
    if requested_at.tzinfo is None or requested_at.utcoffset() is None:
        return False
    current = _utc_now(now)
    age = current - requested_at.astimezone(dt.timezone.utc)
    return -MAX_CLOCK_SKEW <= age <= MAX_REQUEST_AGE


def discard_cancel(active):
    try:
        os.unlink(cancel_path(active))
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RunRequestError(
            "the cancellation request could not be removed"
        ) from exc


def request_undo(root, *, group_id, confirmation, now=None):
    """Queue rollback of the latest recorded run after typed confirmation."""
    if confirmation != "UNDO":
        raise RunRequestError("type UNDO to confirm the rollback")
    if not GROUP_ID.fullmatch(str(group_id)):
        raise RunRequestError("the rollback group is invalid")
    root = Path(root)
    requested_at = _utc_now(now)
    try:
        with connection.lifecycle_lock(root, blocking=False):
            occupant = connection.current(root)
            if occupant is None:
                raise RunRequestError("link a Google account before undoing")
            active = Path(occupant.directory)
            if request_path(active).is_file():
                raise RunAlreadyActive("a mailbox operation is already queued")
            if (active / BACKFILL_FILE).is_file():
                raise RunAlreadyActive(
                    "finish the background backfill before undoing"
                )
            summary = latest_summary(active)
            if summary is None or not hmac.compare_digest(
                    summary["group_id"], str(group_id)):
                raise RunRequestError("only the latest recorded run can be undone")
            atomic_write_json(request_path(active), {
                "version": REQUEST_VERSION,
                "account_hash": _account_hash(occupant.account),
                "requested_at": requested_at.isoformat(timespec="seconds"),
                "scope": "rollback", "message_count": None,
                "rollback_group": str(group_id),
            })
            return int(requested_at.timestamp())
    except connection.ConnectionBusy as exc:
        raise RunAlreadyActive("a mailbox operation is already in progress") from exc


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
        "rollback_group",
    }:
        raise RunRequestError("the immediate-run request has unsupported fields")
    if document.get("version") != REQUEST_VERSION:
        raise RunRequestError("the immediate-run request version is unsupported")
    scope = document.get("scope")
    if scope not in {"recent", "history", "rollback"}:
        raise RunRequestError("the immediate-run request scope is unsupported")
    message_count = _history_count(document.get("message_count"))
    if (scope == "history") != (message_count is not None):
        raise RunRequestError("the immediate-run request scope is inconsistent")
    rollback_group = document.get("rollback_group")
    if scope == "rollback":
        if not GROUP_ID.fullmatch(str(rollback_group)):
            raise RunRequestError("the rollback request group is invalid")
    elif rollback_group is not None:
        raise RunRequestError("the immediate-run request rollback group is inconsistent")
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
