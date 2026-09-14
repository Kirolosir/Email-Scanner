"""Encrypted, verified backups of configuration and bounded run history."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from connection_tokens import DATA_KEY_BYTES, NONCE_BYTES, TokenStoreError
from private_runtime import atomic_write_json, ensure_private_directory


VERSION = 1
ROOT_FILES = {
    "account.json", "taxonomy-confirmation.json", "ai-drafting-approval.json",
    "daily-state.json", "daily-status.json", "retry-queue.json",
}


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _unb64(value):
    return base64.b64decode(value.encode("ascii"), validate=True)


def _archive_bytes(active):
    active = Path(active)
    chosen = [active / name for name in sorted(ROOT_FILES)]
    for directory, pattern in (
        ("review", "*.json"), ("draft-logs", "*"), ("rollback", "*"),
    ):
        try:
            chosen.extend(sorted(
                (path for path in (active / directory).glob(pattern)
                 if path.is_file() and not path.name.startswith(".")),
                key=lambda path: path.stat().st_mtime
            )[-30:])
        except OSError:
            pass
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in chosen:
            if path.is_file():
                archive.write(path, path.relative_to(active).as_posix())
    return output.getvalue()


def create_verified_backup(active, backup_dir, seat_id, provider, *, now=None,
                           retain=30):
    now = now or dt.datetime.now(dt.timezone.utc)
    plaintext = _archive_bytes(active)
    digest = hashlib.sha256(plaintext).hexdigest()
    data_key = secrets.token_bytes(DATA_KEY_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    binding = f"{seat_id}:backup:{VERSION}"
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, binding.encode())
    record = {
        "version": VERSION,
        "seat": seat_id,
        "sha256": digest,
        "wrapped_key": _b64(provider.wrap(data_key, binding)),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    data_key = None
    directory = Path(backup_dir)
    ensure_private_directory(directory)
    stamp = now.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = directory / f"backup-{stamp}.enc.json"
    atomic_write_json(path, record)
    verify_backup(path, seat_id, provider)
    backups = sorted(directory.glob("backup-*.enc.json"))
    for expired in backups[:-max(1, int(retain))]:
        expired.unlink()
    return path


def _decrypt(path, seat_id, provider):
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
        if record.get("version") != VERSION or record.get("seat") != seat_id:
            raise TokenStoreError("backup identity or version is invalid")
        binding = f"{seat_id}:backup:{VERSION}"
        key = provider.unwrap(_unb64(record["wrapped_key"]), binding)
        plaintext = AESGCM(key).decrypt(
            _unb64(record["nonce"]), _unb64(record["ciphertext"]),
            binding.encode(),
        )
        key = None
    except (OSError, ValueError, KeyError, InvalidTag) as exc:
        raise TokenStoreError("backup could not be authenticated") from exc
    if hashlib.sha256(plaintext).hexdigest() != record.get("sha256"):
        raise TokenStoreError("backup digest does not match")
    return plaintext


def verify_backup(path, seat_id, provider):
    plaintext = _decrypt(path, seat_id, provider)
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        for name in archive.namelist():
            parts = PurePosixPath(name).parts
            if not parts or name.startswith("/") or ".." in parts:
                raise TokenStoreError("backup contains an unsafe path")
        bad = archive.testzip()
        if bad is not None:
            raise TokenStoreError("backup archive failed verification")
    return True


def restore_backup(path, destination, seat_id, provider):
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise TokenStoreError("restore destination must be empty")
    ensure_private_directory(destination)
    plaintext = _decrypt(path, seat_id, provider)
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        verify_backup(path, seat_id, provider)
        for item in archive.infolist():
            target = destination.joinpath(*PurePosixPath(item.filename).parts)
            ensure_private_directory(target.parent)
            if not item.is_dir():
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                     0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(archive.read(item))
    return destination
