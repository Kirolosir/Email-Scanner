"""Copy the existing hosted account into one tenant-owned mailbox."""
from __future__ import annotations

import datetime as dt
import os
import shutil
import uuid
from pathlib import Path

import connection
import connection_tokens
from connect_account import build_provider
from private_runtime import ensure_private_directory
from tenant_store import PostgresTenantStore, TenantStoreError


FILES = frozenset({
    "account.json",
    "taxonomy-confirmation.json",
    "ai-drafting-approval.json",
    "daily-state.json",
    "daily-status.json",
    "retry-queue.json",
    "pending-label-setup.json",
})
DIRECTORIES = frozenset({"templates", "review", "draft-logs", "rollback"})
REQUIRED_FILES = frozenset({
    "account.json", "taxonomy-confirmation.json", "ai-drafting-approval.json",
})


def _copy_artifacts(source, destination):
    source = Path(source)
    destination = Path(destination)
    if destination.exists():
        raise TenantStoreError("tenant artifact directory already exists")
    ensure_private_directory(destination)
    for name in FILES:
        item = source / name
        if item.is_file():
            shutil.copy2(item, destination / name)
            os.chmod(destination / name, 0o600)
    for name in DIRECTORIES:
        item = source / name
        if item.is_dir():
            shutil.copytree(item, destination / name)
            for directory, _children, filenames in os.walk(destination / name):
                os.chmod(directory, 0o700)
                for filename in filenames:
                    os.chmod(Path(directory) / filename, 0o600)


def import_legacy_account(root, store, provider, *, now=None):
    """Import without deleting or modifying the legacy connection."""
    now = now or dt.datetime.now(dt.timezone.utc)
    legacy = connection.current(root)
    if legacy is None:
        raise TenantStoreError("no legacy account is connected")
    if any(not (legacy.directory / name).is_file() for name in REQUIRED_FILES):
        raise TenantStoreError("legacy account setup is incomplete")
    user = store.user_for_email(legacy.account)
    token_document = connection_tokens.load_token(legacy, provider)
    mailbox = None
    try:
        mailbox = store.connect_mailbox(
            user.id, user.identity_subject, legacy.account,
            token_document, provider, now=now,
        )
    finally:
        token_document = None

    destination = Path(root) / "mailboxes" / str(mailbox.id)
    staging = destination.with_name(f".{mailbox.id}.import-{uuid.uuid4().hex}")
    try:
        if not destination.exists():
            _copy_artifacts(legacy.directory, staging)
            ensure_private_directory(destination.parent)
            os.replace(staging, destination)
        store.update_mailbox_settings(
            user.id, mailbox.id,
            timezone=legacy.timezone_name,
            run_at=dt.time(legacy.hour, legacy.minute),
            enabled=legacy.enabled,
            max_scan=legacy.max_scan,
            write_limit=legacy.limit,
            max_drafts=legacy.max_drafts,
            now=now,
        )
        store.set_mailbox_setup(user.id, mailbox.id, "ready")
    except Exception as exc:
        if staging.exists():
            shutil.rmtree(staging)
        store.set_mailbox_setup(
            user.id, mailbox.id, "error", error_code="artifact_import_failed"
        )
        raise TenantStoreError("legacy artifact import failed") from exc
    return mailbox


def main(env=None):
    values = os.environ if env is None else env
    root = Path(values.get("HOSTED_STATE_ROOT", ""))
    store = PostgresTenantStore.connect(values.get("DATABASE_URL", ""))
    try:
        provider = build_provider(values.get("CONNECTION_KMS_KEY", ""))
        import_legacy_account(root, store, provider)
    finally:
        store.close()
    print("Existing account imported; legacy state was left unchanged.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TenantStoreError as exc:
        print(f"Import stopped safely ({type(exc).__name__}).")
        raise SystemExit(2)
