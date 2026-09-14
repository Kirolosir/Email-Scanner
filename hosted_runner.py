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

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

import connection
import connection_schedule
import connection_tokens
import account_profile
import campaign
import daily_triage
from connect_account import build_provider
from gmail_auth import SCOPES
from gmail_common import (
    QuotaThrottle, list_message_ids_by_query, normalize_address,
)
from gmail_labeler import UNITS_MESSAGES_MODIFY, fetch_account_labels
from gmail_retry import gmail_execute
from hosted_status import verify_durable_state_root
import hosted_run_request
import hosted_settings
from private_runtime import RunStatus, ensure_private_directory
import setup_labels
from encrypted_backup import create_verified_backup
from retry_queue import RetryQueue
from triage_config import load_triage_label_config
from rollback_journal import group_journals


CONFIG_FILE = "account.json"
TAXONOMY_APPROVAL_FILE = "taxonomy-confirmation.json"
AI_APPROVAL_FILE = "ai-drafting-approval.json"
STATE_FILE = "daily-state.json"
STATUS_FILE = "daily-status.json"
LOCK_DIR = "locks"
REVIEW_DIR = "review"
DRAFT_LOG_DIR = "draft-logs"
RETRY_QUEUE_FILE = "retry-queue.json"
BACKUP_DIR = "backups"
ROLLBACK_DIR = "rollback"
PENDING_LABEL_SETUP = hosted_settings.PENDING_LABEL_SETUP
HISTORY_CHUNK_SIZE = 50
BATCH_HISTORY_CHUNK_SIZE = 200


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
    containers = [
        document.get(key) for key in ("installed", "web")
        if isinstance(document, dict) and isinstance(document.get(key), dict)
    ]
    if len(containers) != 1:
        raise HostedRunnerError(
            "OAuth client must contain exactly one installed or web client"
        )
    container = containers[0]
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


def _refresh_credentials(credentials):
    """Validate the refresh grant before any Gmail operation begins."""
    credentials.refresh(Request())


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


def _read_json_object(path, description):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise HostedRunnerError(
            f"{description} is unavailable ({type(exc).__name__})"
        ) from exc
    if not isinstance(document, dict):
        raise HostedRunnerError(f"{description} must be an object")
    return document


def _pending_label_plan(active, occupant):
    """Validate a saved owner approval before constructing a Gmail client."""
    pending_path = Path(active) / PENDING_LABEL_SETUP
    if not pending_path.is_file():
        return None

    pending = _read_json_object(pending_path, "pending label setup")
    if set(pending) != {"version", "account_config_digest", "labels"}:
        raise HostedRunnerError("pending label setup has unsupported fields")
    if pending.get("version") != 1:
        raise HostedRunnerError("pending label setup has an unsupported version")

    config_path = Path(active) / CONFIG_FILE
    config_document = _read_json_object(config_path, "account configuration")
    if pending.get("account_config_digest") != hosted_settings.document_digest(
        config_document
    ):
        raise HostedRunnerError("pending label setup does not match current settings")

    profile = account_profile.load_profile_document(config_document)
    try:
        account_profile.assert_profile_matches_account(profile, occupant.account)
    except ValueError as exc:
        raise HostedRunnerError("settings belong to a different account") from exc
    config = load_triage_label_config(profile=profile)
    expected = sorted(config.all_names)
    if pending.get("labels") != expected:
        raise HostedRunnerError("pending label setup does not match reviewed labels")
    return pending_path, profile, config


def _apply_pending_label_plan(service, prepared):
    """Create only exact reviewed names after live Gmail identity checking."""
    pending_path, profile, config = prepared
    actual = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get(
            "emailAddress", ""
        )
    )
    try:
        account_profile.assert_profile_matches_account(profile, actual)
    except ValueError as exc:
        raise HostedRunnerError(
            "authenticated Gmail account does not match saved settings"
        ) from exc

    existing = fetch_account_labels(service)
    try:
        plan = setup_labels.plan_label_setup(existing, config)
        _created, failures = setup_labels.apply_label_setup(
            service, config, plan, dry_run=False
        )
    except ValueError as exc:
        raise HostedRunnerError("reviewed Gmail label setup was refused") from exc
    if failures:
        raise HostedRunnerError("one or more reviewed Gmail labels were not created")
    try:
        pending_path.unlink()
    except OSError as exc:
        raise HostedRunnerError(
            f"label setup completion could not be recorded ({type(exc).__name__})"
        ) from exc


def _record_blocked(status_path, code):
    status = RunStatus(status_path)
    status.start("hosted:configuration")
    status.finish(False, {"failures": 1}, [code])


def _review_path(directory, now):
    ensure_private_directory(directory)
    stamp = now.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return directory / f"daily-{stamp}.json"


# A plan can add one category, one evidence label, Needs Review, Processed,
# and one draft. Reserving this upper bound lets a hosted batch finish every
# candidate it reads instead of deferring most of it behind separate caps.
MAX_WRITES_PER_MESSAGE = hosted_settings.MAX_WRITES_PER_MESSAGE


def _complete_batch_limits(message_count):
    message_count = int(message_count)
    if message_count <= 0:
        raise HostedRunnerError("the hosted batch size must be positive")
    return message_count * MAX_WRITES_PER_MESSAGE, message_count


def _history_review_path(directory, now, offset):
    ensure_private_directory(directory)
    stamp = int(now.astimezone(dt.timezone.utc).timestamp())
    return directory / f"history-{stamp}-{offset:05d}.json"


def _rollback_manifest_path(active, group_id, offset=0):
    return Path(active) / ROLLBACK_DIR / f"{group_id}-{offset:05d}.json"


def _undo_group(service, active, group_id, status_path):
    """Undo exactly recorded writes, preserving progress after every change."""
    journals = group_journals(active, group_id)
    labels = fetch_account_labels(service)
    throttle = QuotaThrottle()
    state = daily_triage.DailyState(active / STATE_FILE).load()
    counts = {key: 0 for key in RunStatus.COUNT_KEYS}
    status = RunStatus(status_path)
    status.start("hosted:rollback")
    entries = [entry for journal in journals for entry in journal.document["entries"]]
    status.progress("Undoing previous run", counts, current=0, total=len(entries))
    restore_log = campaign.DraftLog(
        str(Path(active) / ROLLBACK_DIR / f"restore-{group_id}.log"),
        [f"rollback group {group_id}", "message ids moved to Gmail Trash"],
    )
    failures = 0
    completed = 0
    with restore_log:
        for journal in journals:
            for entry in journal.document["entries"]:
                draft_done = entry["draft_undone"] or not entry["draft_id"]
                labels_done = entry["labels_undone"] or not entry["labels"]
                if not draft_done:
                    trashed, missing, errors = campaign.trash_drafts(
                        service, [entry["draft_id"]], throttle, restore_log
                    )
                    if not errors and trashed + missing == 1:
                        journal.mark_progress(entry["message_id"], draft=True)
                        draft_done = True
                        counts["drafted"] += trashed
                    else:
                        failures += 1
                if not labels_done:
                    label_ids = [labels[name] for name in entry["labels"] if name in labels]
                    try:
                        if label_ids:
                            throttle.consume(UNITS_MESSAGES_MODIFY)
                            gmail_execute(service.users().messages().modify(
                                userId="me", id=entry["message_id"],
                                body={"removeLabelIds": label_ids},
                            ))
                        journal.mark_progress(entry["message_id"], labels=True)
                        labels_done = True
                        counts["labeled"] += len(label_ids)
                    except Exception:  # noqa: BLE001 - status remains message-free
                        failures += 1
                if draft_done and labels_done:
                    record = state.record_for(entry["message_id"])
                    if (not entry["draft_id"]
                            or record.get("draft_id", "") == entry["draft_id"]):
                        state.data["messages"].pop(entry["message_id"], None)
                    completed += 1
                status.progress(
                    "Undoing previous run", counts,
                    current=completed, total=len(entries),
                )
    state.data["last_daily_date"] = None
    state.save()
    if failures == 0 and completed == len(entries):
        for journal in journals:
            journal.mark_undone()
    counts["failures"] = failures
    counts["skipped"] = max(0, len(entries) - completed)
    status.finish(failures == 0, counts,
                  ["rollback_incomplete"] if failures else [])
    return 1 if failures else 0


def _latest_counts(status_path):
    try:
        with Path(status_path).open(encoding="utf-8") as handle:
            document = json.load(handle)
        counts = (document.get("last_run") or {}).get("counts") or {}
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}
    return {
        key: value for key, value in counts.items()
        if key in RunStatus.COUNT_KEYS
        and isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }


def _add_counts(total, addition):
    for key in RunStatus.COUNT_KEYS:
        total[key] = int(total.get(key, 0)) + int(addition.get(key, 0))
    return total


def run_if_due(env=None, *, now=None, service_builder=build,
               credential_refresher=None):
    env = env if env is not None else os.environ
    now = now or dt.datetime.now(dt.timezone.utc)
    root = Path(_required_env(env, "HOSTED_STATE_ROOT"))
    key_name = _required_env(env, "CONNECTION_KMS_KEY")
    client_path = Path(_required_env(env, "GMAIL_CREDENTIALS_PATH"))
    require_mount = str(env.get("HOSTED_REQUIRE_MOUNTPOINT", "true")).lower() \
        not in {"false", "0", "no"}
    verify_durable_state_root(root, require_mountpoint=require_mount)

    with connection.lifecycle_lock(root):
        occupant = connection.current(root)
        if occupant is None:
            print("No Gmail account is connected; nothing ran.")
            return 0

        active = Path(occupant.directory)
        status_path = active / STATUS_FILE
        retry_queue = RetryQueue(active / RETRY_QUEUE_FILE)
        try:
            run_request = hosted_run_request.consume_request(
                active, occupant, now=now
            )
        except hosted_run_request.RunRequestError as exc:
            try:
                hosted_run_request.discard_request(active)
            except hosted_run_request.RunRequestError:
                pass
            _record_blocked(status_path, "run_request_invalid")
            print(f"Immediate run stopped safely ({type(exc).__name__}).")
            return 2

        force_requested = run_request is not None
        if force_requested and not occupant.enabled:
            _record_blocked(status_path, "account_disabled")
            print("The connected account is disabled; no Gmail contact occurred.")
            return 2

        missing = [path.name for path in _required_account_files(active)
                   if not path.is_file()]
        if missing:
            _record_blocked(status_path, "account_setup_incomplete")
            print("Connected account setup is incomplete; no Gmail contact occurred.")
            return 2

        try:
            prepared_labels = _pending_label_plan(active, occupant)
        except (HostedRunnerError, ValueError) as exc:
            _record_blocked(status_path, "label_setup_invalid")
            print(f"Gmail label setup stopped safely ({type(exc).__name__}).")
            return 2

        last_completed = _last_completed_date(active / STATE_FILE)
        due, reason = connection_schedule.is_due(
            occupant, now, last_completed_date=last_completed
        )
        retry_ids = retry_queue.due(now, occupant.max_scan)
        retry_requested = bool(retry_ids and not due and not force_requested)
        if (not due and not force_requested and prepared_labels is None
                and not retry_requested):
            print(f"No run due: {reason}.")
            return 0

        provider = build_provider(key_name)
        token_document = connection_tokens.load_token(occupant, provider)
        try:
            credentials = hosted_credentials(token_document, client_path)
        finally:
            token_document = None
        try:
            (credential_refresher or _refresh_credentials)(credentials)
        except RefreshError:
            credentials = None
            _record_blocked(status_path, "gmail_reauthorization_required")
            print("Google authorization needs to be renewed; no Gmail contact occurred.")
            return 2
        gmail_service = service_builder("gmail", "v1", credentials=credentials)

        if run_request and run_request.get("scope") == "rollback":
            try:
                code = _undo_group(
                    gmail_service, active, run_request["rollback_group"], status_path
                )
            except Exception as exc:  # noqa: BLE001 - status remains message-free
                _record_blocked(status_path, "rollback_failed")
                print(f"Previous-run undo stopped safely ({type(exc).__name__}).")
                return 1
            return code

        if prepared_labels is not None:
            try:
                _apply_pending_label_plan(gmail_service, prepared_labels)
            except HostedRunnerError as exc:
                _record_blocked(status_path, "label_setup_failed")
                print(f"Gmail label setup stopped safely ({type(exc).__name__}).")
                return 2
            if not due and not force_requested and not retry_requested:
                print("Reviewed Gmail labels are ready; no daily run was due.")
                return 0

        history_count = (
            run_request.get("message_count")
            if run_request and run_request.get("scope") == "history"
            else None
        )

        rollback_group = str(int(now.timestamp()))

        def _argv(scan_limit, review_path, *, history=False, offset=0):
            write_limit, draft_limit = _complete_batch_limits(scan_limit)
            values = [
                "daily",
                "--account-config", str(active / CONFIG_FILE),
                "--taxonomy-confirmation", str(active / TAXONOMY_APPROVAL_FILE),
                "--ai-drafting-approval", str(active / AI_APPROVAL_FILE),
                "--templates", str(active / "templates"),
                "--state-path", str(active / STATE_FILE),
                "--status-path", str(status_path),
                "--lock-dir", str(active / LOCK_DIR),
                "--review-report", str(review_path),
                "--rollback-manifest", str(_rollback_manifest_path(
                    active, rollback_group, offset
                )),
                "--rollback-group", rollback_group,
                "--max-scan", str(scan_limit),
                "--limit", str(write_limit),
                "--max-drafts", str(draft_limit),
                "--scheduled", "--apply", "--yes",
            ]
            if history:
                values.append("--history-scan")
            if force_requested or retry_requested:
                values.append("--force")
            return values

        def _update_reliability(code, *, apply_result=True):
            if apply_result:
                result = getattr(daily_triage.main, "last_result", {}) or {}
                retry_queue.update(
                    result.get("failed_ids", ()),
                    result.get("completed_ids", ()), now=now,
                )
            status = RunStatus(status_path)
            run = status.data.get("last_run") or {}
            counts = dict(run.get("counts") or {})
            counts["retry_queued"] = len(retry_queue)
            error_codes = list(run.get("safe_error_codes") or [])
            if (not callable(getattr(provider, "wrap", None))
                    or not callable(getattr(provider, "unwrap", None))):
                status.finish(code == 0, counts, error_codes)
                return code
            try:
                create_verified_backup(
                    active, active / BACKUP_DIR, occupant.id, provider, now=now
                )
                counts["backup_verified"] = 1
            except Exception as exc:  # noqa: BLE001 - status remains PII-free
                counts["backup_failures"] = 1
                error_codes.append("backup_verification_failed")
                print(f"Encrypted backup stopped safely ({type(exc).__name__}).")
            status.finish(code == 0, counts, error_codes)
            return code

        # DraftLog uses the profile's configured path. Keep hosted artifacts on
        # the durable active volume even if a restored profile names an old local
        # path by changing only the process-local working value the runner owns.
        old_log_dir = campaign.DRAFT_LOG_DIR
        campaign.DRAFT_LOG_DIR = str(active / DRAFT_LOG_DIR)
        try:
            if history_count is None:
                scan_limit = len(retry_ids) if retry_requested else occupant.max_scan
                argv = _argv(
                    scan_limit,
                    _review_path(active / REVIEW_DIR, now),
                )
                if retry_requested:
                    code = daily_triage.main(
                        argv, gmail_service=gmail_service,
                        message_ids_override=retry_ids,
                    )
                else:
                    code = daily_triage.main(argv, gmail_service=gmail_service)
                return _update_reliability(code)

            overall_status = RunStatus(status_path)
            overall_status.start("daily:history-batch")
            overall_status.progress(
                "Finding previous emails", current=0, total=history_count
            )
            try:
                actual_account = normalize_address(
                    gmail_execute(
                        gmail_service.users().getProfile(userId="me")
                    ).get("emailAddress", "")
                )
                if not connection.same_account(actual_account, occupant.account):
                    raise HostedRunnerError(
                        "authenticated Gmail account does not match the connection"
                    )
                message_ids = list_message_ids_by_query(
                    gmail_service, daily_triage.build_history_query(),
                    QuotaThrottle(), max_scan=history_count, progress=False,
                )
            except Exception as exc:  # noqa: BLE001 - status stays PII-free
                overall_status.finish(
                    False, {"failures": 1}, ["history_preflight_failed"]
                )
                print(f"History scan stopped safely ({type(exc).__name__}).")
                return 1

            aggregate = {key: 0 for key in RunStatus.COUNT_KEYS}
            if not message_ids:
                overall_status.finish(True, aggregate)
                print("No eligible historical messages were found.")
                return _update_reliability(0, apply_result=False)

            overall_status = RunStatus(status_path)
            overall_status.progress(
                "Processing previous emails", aggregate,
                current=0, total=len(message_ids),
            )

            chunk_size = (
                BATCH_HISTORY_CHUNK_SIZE
                if len(message_ids) > 100 else HISTORY_CHUNK_SIZE
            )
            for offset in range(0, len(message_ids), chunk_size):
                chunk = message_ids[offset:offset + chunk_size]
                argv = _argv(
                    len(chunk),
                    _history_review_path(active / REVIEW_DIR, now, offset),
                    history=True, offset=offset,
                )
                code = daily_triage.main(
                    argv, gmail_service=gmail_service,
                    message_ids_override=chunk,
                )
                result = getattr(daily_triage.main, "last_result", {}) or {}
                retry_queue.update(
                    result.get("failed_ids", ()),
                    result.get("completed_ids", ()), now=now,
                )
                _add_counts(aggregate, _latest_counts(status_path))
                queued_failures = bool(result.get("failed_ids"))
                if code != 0 and not queued_failures:
                    status = RunStatus(status_path)
                    status.finish(
                        False, aggregate, ["history_chunk_failed"]
                    )
                    print(
                        f"History scan paused after {offset + len(chunk)} "
                        "selected messages; completed work was saved."
                    )
                    return code
                status = RunStatus(status_path)
                completed = offset + len(chunk)
                if completed < len(message_ids):
                    status.start("daily:history-batch")
                    status.progress(
                        "Processing previous emails", aggregate,
                        current=completed, total=len(message_ids),
                    )
                else:
                    status.finish(True, aggregate)
                print(
                    f"History progress: {completed} of "
                    f"{len(message_ids)} selected messages checked."
                )
            return _update_reliability(0, apply_result=False)
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
