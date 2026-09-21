"""Lease-bound execution boundary for one tenant mailbox job."""
from __future__ import annotations

import datetime as dt
import argparse
import os
import time
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
        if error_code != "setup_incomplete" and job.attempt_number < 5:
            delay = min(30, 2 ** job.attempt_number)
            store.retry_job(
                job.id, worker_id, error_code=error_code,
                run_after=dt.datetime.now(dt.timezone.utc)
                + dt.timedelta(minutes=delay),
            )
        else:
            store.finish_job(
                job.id, worker_id, succeeded=False, error_code=error_code
            )
        return False
    finally:
        token_document = None
    return True


def main(processor=None, env=None, *, once=False, sleeper=time.sleep):
    values = os.environ if env is None else env
    from connect_account import build_provider  # noqa: PLC0415
    from tenant_processor import TenantMailboxProcessor  # noqa: PLC0415

    store = PostgresTenantStore.connect(values.get("DATABASE_URL", ""))
    worker_id = f"worker-{uuid.uuid4()}"
    try:
        provider = build_provider(values.get("CONNECTION_KMS_KEY", ""))
        processor = processor or TenantMailboxProcessor(
            values.get("GMAIL_CREDENTIALS_PATH", "")
        )
        while True:
            handled = process_one(
                store, values.get("HOSTED_STATE_ROOT", ""), provider,
                processor, worker_id=worker_id,
            )
            if once:
                break
            if not handled:
                sleeper(5)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a tenant mailbox worker.")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        raise SystemExit(main(once=args.once))
    except TenantStoreError as exc:
        print(f"Worker stopped safely ({type(exc).__name__}).")
        raise SystemExit(2)
