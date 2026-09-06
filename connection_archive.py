"""Disconnect: what happens to each artifact when an account leaves.

The files a connected account leaves behind are not one category, and a single
policy for all of them would be wrong in at least one direction. Four kinds:

  CREDENTIAL   the token. Destroyed, and revoked at Google. Keeping an
               encrypted token "in case they return" is keeping a live
               credential for a mailbox nobody serves any more.

  CONSENT      the taxonomy confirmation and the AI-drafting approval.
               Archived, but INERT: nothing reads them back. Disconnecting is
               the clearest available signal that somebody has withdrawn, and
               silently resuming unattended drafting months later on the
               strength of a sentence typed before that withdrawal is the
               failure this project already rejected once - a consent artifact
               broader than the behaviour it authorises. They are kept only as
               a record of who consented, and when.

  CONFIG       account.json. Archived and RESTORABLE. Taxonomy, labels,
               guidance and signature are real setup work and hold no
               credential. Because drafting_policy_digest binds an approval to
               the configuration, restoring the config and re-running the
               ceremony regenerates a valid approval in one operator action:
               config survives the gap, permission does not.

  HISTORY      the journal, status document, review reports, draft logs and
               scrubbed diagnostics. Archived. The journal is additionally
               restorable, because restoring it is what stops a returning
               account re-drafting messages it already handled.

REVOCATION IS INJECTED. This module never contacts Google. A revoker is passed
in, and if none is supplied that fact is recorded in the manifest rather than
passed over in silence. If revocation fails the local token is destroyed
anyway: a local copy nobody can revoke is worse than no local copy.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
from pathlib import Path

from connection import ACTIVE_DIR, normalize_account, record_path
from message_safety import opaque_id
from private_runtime import atomic_write_json, ensure_private_directory


ARCHIVE_DIR = "archive"
MANIFEST_FILE = "archive-manifest.json"
MANIFEST_VERSION = 1

DESTROY = "destroy"
ARCHIVE = "archive"
ARCHIVE_RESTORABLE = "archive_restorable"

# Every artifact the connected account can leave behind, with an explicit
# disposition. A name absent from this table is archived and never restored -
# the conservative choice in both directions - and test_connection_archive
# asserts the table actually covers what the system produces, so a new
# artifact cannot quietly acquire a default policy nobody chose.
DISPOSITION = {
    "token.enc.json": (DESTROY, "credential"),
    "taxonomy-confirmation.json": (ARCHIVE, "consent"),
    "ai-drafting-approval.json": (ARCHIVE, "consent"),
    "account.json": (ARCHIVE_RESTORABLE, "config"),
    "daily-state.json": (ARCHIVE_RESTORABLE, "history"),
    "daily-status.json": (ARCHIVE, "history"),
    "failures.log": (ARCHIVE, "history"),
    "failures.log.1": (ARCHIVE, "history"),
    "review": (ARCHIVE, "history"),
    "draft-logs": (ARCHIVE, "history"),
    "locks": (DESTROY, "coordination"),
}

# Restoration is deliberately narrow. There is no entry here for a token or a
# consent record, and no code below that could return one.
RESTORABLE = frozenset(
    name for name, (kind, _class) in DISPOSITION.items()
    if kind == ARCHIVE_RESTORABLE
)

UNKNOWN_DISPOSITION = (ARCHIVE, "unrecognized")


class ArchiveError(RuntimeError):
    pass


def archive_root(root):
    return Path(root) / ARCHIVE_DIR


def archive_path(root, account):
    """Where one account's archive lives.

    Named by opaque_id rather than the address. This is worth being precise
    about: the archived config still contains the address inside it, so this
    does not hide who used the system from anyone who can read the files. What
    it does buy is that a directory listing - in a backup index, a log line, a
    screen share - does not enumerate addresses.
    """
    return archive_root(root) / opaque_id(normalize_account(account), 16)


def _move(source, destination):
    ensure_private_directory(destination.parent)
    shutil.move(str(source), str(destination))


def _destroy(path):
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        return True
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def disconnect(connection, root, *, revoke=None, token_document=None,
               now=None):
    """Vacate the connection, disposing of each artifact by its own policy.

    `revoke` is an injected callable. Nothing here contacts Google; if no
    revoker is supplied the manifest records that revocation was not
    attempted, so an unrevoked grant is visible rather than assumed.

    Returns a manifest describing exactly what happened.
    """
    stamp = (now or dt.datetime.now(dt.timezone.utc)).isoformat(
        timespec="seconds"
    )
    active = Path(connection.directory)
    destination = archive_path(root, connection.account)

    # Revoke first, while the token still exists, but never let the outcome
    # decide whether the local copy is destroyed.
    revocation = "not attempted"
    if revoke is not None:
        try:
            revocation = "revoked" if revoke(token_document) else "refused"
        except Exception as exc:  # noqa: BLE001 - an injected revoker may raise
            revocation = f"failed ({type(exc).__name__})"

    destroyed, archived = [], []
    if active.exists():
        for entry in sorted(active.iterdir()):
            kind, _class = DISPOSITION.get(entry.name, UNKNOWN_DISPOSITION)
            if kind == DESTROY:
                _destroy(entry)
                destroyed.append(entry.name)
            else:
                _move(entry, destination / entry.name)
                archived.append(entry.name)

    manifest = {
        "version": MANIFEST_VERSION,
        "archived_at": stamp,
        "account_hash": opaque_id(normalize_account(connection.account), 16),
        "connected_at": connection.connected_at,
        "revocation": revocation,
        "destroyed": destroyed,
        "archived": archived,
        "restorable": sorted(name for name in archived if name in RESTORABLE),
    }
    ensure_private_directory(destination)
    atomic_write_json(destination / MANIFEST_FILE, manifest)

    # The active directory and the connection record go last, so a failure
    # part-way through leaves the deployment still holding its connection
    # rather than orphaned in a half-vacant state.
    if active.exists():
        shutil.rmtree(active, ignore_errors=True)
    try:
        os.unlink(record_path(root))
    except FileNotFoundError:
        pass
    return manifest


def read_manifest(root, account):
    """The manifest for one account's archive, or None."""
    path = archive_path(root, account) / MANIFEST_FILE
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def restorable(root, account):
    """What an archive can give back to a returning account.

    Only configuration and the journal, and only for an archive whose hash
    matches this address. Consent records and tokens are absent by
    construction: they are not in RESTORABLE, and nothing here reads them.
    """
    manifest = read_manifest(root, account)
    if manifest is None:
        return []
    if manifest.get("account_hash") != opaque_id(normalize_account(account), 16):
        return []
    directory = archive_path(root, account)
    return sorted(
        name for name in manifest.get("restorable", [])
        if name in RESTORABLE and (directory / name).exists()
    )


def restore(connection, root, account):
    """Copy the restorable artifacts back into a fresh active directory.

    Refuses to overwrite: restoration is for a newly reconnected account, not
    a way to roll a live connection backwards onto older state.
    """
    available = restorable(root, account)
    if not available:
        return []

    directory = archive_path(root, account)
    active = Path(connection.directory)
    ensure_private_directory(active)
    restored = []
    for name in available:
        target = active / name
        if target.exists():
            raise ArchiveError(
                f"{name} already exists in the active connection; refusing "
                "to overwrite live state with an archived copy"
            )
        shutil.copy2(directory / name, target)
        os.chmod(target, 0o600)
        restored.append(name)
    return restored
