"""Run the connected Gmail account when its local schedule is due.

This is the short-lived hosted execution boundary. It decrypts the refresh
token in memory, combines it with the separately stored OAuth client, builds a
Gmail service, and injects that service into daily_triage. No plaintext token
file is ever created.

The timer may invoke this every fifteen minutes. connection_schedule decides
whether the account is actually due, and daily_triage's own journal remains a
second same-day/idempotency gate. A connected account without reviewed labels
and approvals is blocked before any Gmail request.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

import connection
import connection_schedule
import connection_tokens
import campaign
import daily_triage
from connect_account import build_provider
from gmail_auth import SCOPES
from hosted_status import verify_durable_state_root
from private_runtime import RunStatus, ensure_private_directory


CONFIG_FILE = "account.json"
TAXONOMY_APPROVAL_FILE = "taxonomy-confirmation.json"
AI_APPROVAL_FILE = "ai-drafting-approval.json"
STATE_FILE = "daily-state.json"
STATUS_FILE = "daily-status.json"
LOCK_DIR = "locks"
REVIEW_DIR = "review"
DRAFT_LOG_DIR = "draft-logs"


class HostedRunnerError(RuntimeError):
    """Carries no token, client secret, account address, or message data."""


def _required_env(env, name):
    value = str(env.get(name, "") or "").strip()
    if not value:
        raise HostedRunnerError(f"{name} is required")
    return value


def _client_details(path):
    """Validated OAuth client fields without returning the source document."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise HostedRunnerError(
            f"OAuth client configuration is unavailable ({type(exc).__name__})"
        ) from exc
    container = document.get("installed") if isinstance(document, dict) else None
    if not isinstance(container, dict):
        raise HostedRunnerError("OAuth client must be an installed-app client")
    required = ("client_id", "client_secret", "token_uri")
    if any(not isinstance(container.get(key), str) or not container[key]
           for key in required):
        raise HostedRunnerError("OAuth client configuration is incomplete")
    return tuple(container[key] for key in required)


def hosted_credentials(token_document, client_path):
    """Build refreshable credentials while keeping the token in memory."""
    if not isinstance(token_document, dict):
        raise HostedRunnerError("stored credential is malformed")
    refresh_token = token_document.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise HostedRunnerError("stored credential has no refresh token")
    client_id, client_secret, token_uri = _client_details(client_path)
    return Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=token_uri,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )


def _last_completed_date(state_path):
    try:
        with Path(state_path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    except OSError as exc:
        raise HostedRunnerError(
            f"daily journal is unavailable ({type(exc).__name__})"
        ) from exc
    raw = document.get("last_daily_date") if isinstance(document, dict) else None
    if raw is None:
        return None
    try:
        return dt.date.fromisoformat(raw)
    except (TypeError, ValueError) as exc:
        raise HostedRunnerError("daily journal has an invalid completion date") from exc


def _required_account_files(active):
    return (
        active / CONFIG_FILE,
        active / TAXONOMY_APPROVAL_FILE,
        active / AI_APPROVAL_FILE,
    )


def _record_blocked(status_path, code):
    status = RunStatus(status_path)
    status.start("hosted:configuration")
    status.finish(False, {"failures": 1}, [code])


def _review_path(directory, now):
    ensure_private_directory(directory)
    stamp = now.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return directory / f"daily-{stamp}.json"


def run_if_due(env=None, *, now=None, service_builder=build):
    env = env if env is not None else os.environ
    now = now or dt.datetime.now(dt.timezone.utc)
    root = Path(_required_env(env, "HOSTED_STATE_ROOT"))
    key_name = _required_env(env, "CONNECTION_KMS_KEY")
    client_path = Path(_required_env(env, "GMAIL_CREDENTIALS_PATH"))
    require_mount = str(env.get("HOSTED_REQUIRE_MOUNTPOINT", "true")).lower() \
        not in {"false", "0", "no"}
    verify_durable_state_root(root, require_mountpoint=require_mount)

    occupant = connection.current(root)
    if occupant is None:
        print("No Gmail account is connected; nothing ran.")
        return 0

    active = Path(occupant.directory)
    status_path = active / STATUS_FILE
    missing = [path.name for path in _required_account_files(active)
               if not path.is_file()]
    if missing:
        _record_blocked(status_path, "account_setup_incomplete")
        print("Connected account setup is incomplete; no Gmail contact occurred.")
        return 2

    last_completed = _last_completed_date(active / STATE_FILE)
    due, reason = connection_schedule.is_due(
        occupant, now, last_completed_date=last_completed
    )
    if not due:
        print(f"No run due: {reason}.")
        return 0

    provider = build_provider(key_name)
    token_document = connection_tokens.load_token(occupant, provider)
    try:
        credentials = hosted_credentials(token_document, client_path)
    finally:
        token_document = None
    gmail_service = service_builder("gmail", "v1", credentials=credentials)

    review_path = _review_path(active / REVIEW_DIR, now)
    argv = [
        "daily",
        "--account-config", str(active / CONFIG_FILE),
        "--taxonomy-confirmation", str(active / TAXONOMY_APPROVAL_FILE),
        "--ai-drafting-approval", str(active / AI_APPROVAL_FILE),
        "--templates", str(active / "templates"),
        "--state-path", str(active / STATE_FILE),
        "--status-path", str(status_path),
        "--lock-dir", str(active / LOCK_DIR),
        "--review-report", str(review_path),
        "--max-scan", str(occupant.max_scan),
        "--limit", str(occupant.limit),
        "--max-drafts", str(occupant.max_drafts),
        "--scheduled", "--apply", "--yes",
    ]

    # DraftLog uses the profile's configured path. Keep hosted artifacts on
    # the durable active volume even if a restored profile names an old local
    # path by changing only the process-local working value the runner owns.
    old_log_dir = campaign.DRAFT_LOG_DIR
    campaign.DRAFT_LOG_DIR = str(active / DRAFT_LOG_DIR)
    try:
        return daily_triage.main(argv, gmail_service=gmail_service)
    finally:
        campaign.DRAFT_LOG_DIR = old_log_dir
        credentials = None
        gmail_service = None


def main():
    try:
        return run_if_due()
    except Exception as exc:  # noqa: BLE001 - timer must fail without detail
        print(f"Hosted triage stopped safely ({type(exc).__name__}).",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
