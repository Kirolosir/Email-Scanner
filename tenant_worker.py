"""Lease-bound execution boundary for one tenant mailbox job."""
from __future__ import annotations

import datetime as dt
import os
import uuid
from pathlib import Path

from mailbox_tokens import open_mailbox_token
from tenant_store import PostgresTenantStore, TenantStoreError


REQUIRED_ARTIFACTS = (
    "account.json",
    "taxonomy-confirmation.json",
    "ai-drafting-approval.json",
)


class TenantWorkerError(RuntimeError):
    """A worker failure whose message contains no mailbox data."""


def artifact_directory(state_root, mailbox_id):
    mailbox_uuid = uuid.UUID(str(mailbox_id))
    return Path(state_root) / "mailboxes" / str(mailbox_uuid)


def _require_artifacts(directory):
    missing = [name for name in REQUIRED_ARTIFACTS
               if not (Path(directory) / name).is_file()]
    if missing:
        raise TenantWorkerError("mailbox setup artifacts are incomplete")


def process_one(store, state_root, provider, processor, *, worker_id,
                now=None):
    """Claim and process one job, preserving ownership through completion."""
    now = now or dt.datetime.now(dt.timezone.utc)
    job = store.claim_next_job(worker_id, now=now)
    if job is None:
        return False
    token_document = None
    try:
        mailbox = store.worker_mailbox(job.id, job.mailbox_id)
        directory = artifact_directory(state_root, mailbox.id)
        _require_artifacts(directory)
        record = store.worker_credentials(job.id, job.mailbox_id)
        token_document = open_mailbox_token(mailbox.id, record, provider)

        def progress(processed_count):
            store.update_job_progress(
                job.id, worker_id, processed_count,
                now=dt.datetime.now(dt.timezone.utc),
            )

        processor(job, mailbox, directory, token_document, progress)
        store.finish_job(job.id, worker_id, succeeded=True)
    except Exception as exc:  # noqa: BLE001 - store only a bounded safe code
        error_code = (
            "setup_incomplete" if isinstance(exc, TenantWorkerError)
            else "mailbox_job_failed"
        )
        store.finish_job(
            job.id, worker_id, succeeded=False, error_code=error_code
        )
        return False
    finally:
        token_document = None
    return True


def main(processor, env=None):
    values = os.environ if env is None else env
    from connect_account import build_provider  # noqa: PLC0415

    store = PostgresTenantStore.connect(values.get("DATABASE_URL", ""))
    worker_id = f"worker-{uuid.uuid4()}"
    try:
        provider = build_provider(values.get("CONNECTION_KMS_KEY", ""))
        process_one(
            store, values.get("HOSTED_STATE_ROOT", ""), provider, processor,
            worker_id=worker_id,
        )
    finally:
        store.close()
    return 0
