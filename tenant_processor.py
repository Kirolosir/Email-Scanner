"""Mailbox-scoped execution of daily and historical triage jobs."""
from __future__ import annotations

import inspect
import json
from pathlib import Path

from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build

import campaign
import daily_triage
from gmail_common import QuotaThrottle, list_message_ids_by_query, normalize_address
from gmail_retry import gmail_execute
from hosted_runner import (
    hosted_credentials,
    _apply_pending_label_plan,
    _pending_label_plan,
    _refresh_credentials,
)
from private_runtime import atomic_write_json, ensure_private_directory


MAX_WRITE_WORKERS = 4


class TenantProcessorError(RuntimeError):
    """A mailbox processing failure with no message or credential detail."""


def _group_id(job_id):
    return str(job_id.int % (10 ** 16)).zfill(16)


def _selection_path(directory, job_id):
    return Path(directory) / "jobs" / f"{job_id}.json"


def _load_selection(path, job_id):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TenantProcessorError("backfill selection is unreadable") from exc
    if (not isinstance(document, dict) or document.get("version") != 1
            or document.get("job_id") != str(job_id)
            or not isinstance(document.get("message_ids"), list)
            or not all(isinstance(item, str) for item in document["message_ids"])):
        raise TenantProcessorError("backfill selection is invalid")
    return document["message_ids"]


class TenantMailboxProcessor:
    def __init__(self, client_path, *, service_builder=build,
                 credential_refresher=None, triage_main=None,
                 history_lister=None, credential_builder=None):
        self.client_path = Path(client_path)
        self.service_builder = service_builder
        self.credential_refresher = credential_refresher or _refresh_credentials
        self.triage_main = triage_main or daily_triage.main
        self.history_lister = history_lister or list_message_ids_by_query
        self.credential_builder = credential_builder or hosted_credentials

    def _services(self, token_document):
        credentials = self.credential_builder(token_document, self.client_path)
        try:
            self.credential_refresher(credentials)
        except RefreshError as exc:
            raise TenantProcessorError("Gmail authorization must be renewed") from exc
        services = [self.service_builder(
            "gmail", "v1", credentials=credentials
        )]
        for _ in range(MAX_WRITE_WORKERS - 1):
            services.append(self.service_builder(
                "gmail", "v1", credentials=credentials
            ))
        return credentials, services

    @staticmethod
    def _argv(job, mailbox, directory, scan_limit, *, history, offset):
        group_id = _group_id(job.id)
        review = Path(directory) / "review" / f"job-{job.id}-{offset:05d}.json"
        rollback = (
            Path(directory) / "rollback" /
            f"{group_id}-{offset:05d}.json"
        )
        values = [
            "daily",
            "--account-config", str(Path(directory) / "account.json"),
            "--taxonomy-confirmation",
            str(Path(directory) / "taxonomy-confirmation.json"),
            "--ai-drafting-approval",
            str(Path(directory) / "ai-drafting-approval.json"),
            "--templates", str(Path(directory) / "templates"),
            "--state-path", str(Path(directory) / "daily-state.json"),
            "--status-path", str(Path(directory) / "daily-status.json"),
            "--lock-dir", str(Path(directory) / "locks"),
            "--review-report", str(review),
            "--rollback-manifest", str(rollback),
            "--rollback-group", group_id,
            "--max-scan", str(scan_limit),
            "--limit", str(mailbox.write_limit),
            "--max-drafts", str(mailbox.max_drafts),
            "--scheduled", "--apply", "--yes", "--force",
        ]
        if history:
            values.append("--history-scan")
        return values

    def _run_chunk(self, job, mailbox, directory, services, message_ids,
                   *, history, offset):
        argv = self._argv(
            job, mailbox, directory,
            len(message_ids) if message_ids is not None else
            (job.requested_count or mailbox.max_scan),
            history=history, offset=offset,
        )
        kwargs = {"gmail_service": services[0]}
        if message_ids is not None:
            kwargs["message_ids_override"] = message_ids
        if "gmail_write_services" in inspect.signature(
                self.triage_main).parameters:
            kwargs["gmail_write_services"] = services
        code = self.triage_main(argv, **kwargs)
        if code != 0:
            raise TenantProcessorError("mailbox processing did not complete")
        result = getattr(self.triage_main, "last_result", {}) or {}
        return len(set(result.get("completed_ids", ()))
                   | set(result.get("failed_ids", ())))

    def _history_ids(self, job, mailbox, directory, service):
        path = _selection_path(directory, job.id)
        if path.exists():
            return _load_selection(path, job.id)
        actual = normalize_address(gmail_execute(
            service.users().getProfile(userId="me")
        ).get("emailAddress", ""))
        if actual != normalize_address(mailbox.address):
            raise TenantProcessorError("Gmail identity does not match mailbox")
        message_ids = self.history_lister(
            service, daily_triage.build_history_query(), QuotaThrottle(),
            max_scan=job.requested_count or mailbox.max_scan, progress=False,
        )
        ensure_private_directory(path.parent)
        atomic_write_json(path, {
            "version": 1, "job_id": str(job.id),
            "message_ids": list(message_ids),
        })
        return list(message_ids)

    def __call__(self, job, mailbox, directory, token_document, progress):
        credentials = None
        services = []
        old_log_dir = campaign.DRAFT_LOG_DIR
        try:
            credentials, services = self._services(token_document)
            campaign.DRAFT_LOG_DIR = str(Path(directory) / "draft-logs")
            prepared_labels = _pending_label_plan(directory, mailbox)
            if prepared_labels is not None:
                _apply_pending_label_plan(services[0], prepared_labels)
            if job.kind != "backfill":
                processed = self._run_chunk(
                    job, mailbox, directory, services, None,
                    history=False, offset=job.processed_count,
                )
                progress(processed)
                return

            message_ids = self._history_ids(
                job, mailbox, directory, services[0]
            )
            offset = min(job.processed_count, len(message_ids))
            while offset < len(message_ids):
                chunk = message_ids[offset:offset + job.group_size]
                self._run_chunk(
                    job, mailbox, directory, services, chunk,
                    history=True, offset=offset,
                )
                offset += len(chunk)
                progress(offset)
        finally:
            campaign.DRAFT_LOG_DIR = old_log_dir
            credentials = None
            services = []
