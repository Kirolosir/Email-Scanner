"""Validated settings bundle for one tenant-owned mailbox."""
from __future__ import annotations

from pathlib import Path

import approve_account
import hosted_settings
from private_runtime import atomic_write_json, ensure_private_directory
from tenant_store import TenantStoreError
from tenant_worker import artifact_directory


def save_mailbox_settings(store, state_root, user_id, mailbox_id, form,
                          *, now=None):
    mailbox = store.mailbox_for_user(user_id, mailbox_id)
    try:
        document, profile, run_at, limits = hosted_settings.build_settings_document(
            mailbox, form
        )
        taxonomy_document, drafting_document = approve_account.build_documents(
            profile
        )
    except (hosted_settings.SettingsError, ValueError):
        raise
    if drafting_document is None:
        raise hosted_settings.SettingsError(
            "drafting approval was not produced"
        )

    directory = artifact_directory(state_root, mailbox_id)
    store.begin_mailbox_setup(user_id, mailbox_id)
    try:
        ensure_private_directory(directory)
        atomic_write_json(directory / "account.json", document)
        atomic_write_json(
            directory / "taxonomy-confirmation.json", taxonomy_document
        )
        atomic_write_json(
            directory / "ai-drafting-approval.json", drafting_document
        )
        atomic_write_json(
            directory / hosted_settings.PENDING_LABEL_SETUP,
            {
                "version": 1,
                "account_config_digest": hosted_settings.document_digest(
                    document
                ),
                "labels": sorted(
                    [entry["label"] for entry in document["taxonomy"]]
                    + list(document["system_labels"].values())
                ),
            },
        )
        hour, minute = (int(value) for value in run_at.split(":"))
        import datetime as dt  # noqa: PLC0415 - keeps parsing beside commit

        store.update_mailbox_settings(
            user_id, mailbox_id, timezone=profile.timezone,
            run_at=dt.time(hour, minute), enabled=True,
            max_scan=limits["max_scan"], write_limit=limits["limit"],
            max_drafts=limits["max_drafts"], now=now,
        )
        store.set_mailbox_setup(user_id, mailbox_id, "ready")
    except Exception as exc:
        store.set_mailbox_setup(
            user_id, mailbox_id, "error", error_code="settings_save_failed"
        )
        if isinstance(exc, (hosted_settings.SettingsError, TenantStoreError)):
            raise
        raise hosted_settings.SettingsError(
            "settings could not be saved; mailbox remains paused"
        ) from exc
    return mailbox
