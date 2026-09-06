"""Envelope-encrypted storage for the connected account's OAuth refresh token.

WHY THIS IS NOT broker_crypto.py. That module seals a token to a public key so
the broker can encrypt but never decrypt - "a stolen broker disk yields
ciphertext, not a Gmail token" - and it works because the OPERATOR decrypts on
their own machine. A scheduler cannot borrow that. It has to open a sleeping
person's mailbox at 6pm, so it must hold a key that decrypts their token
unattended.

The irreducible consequence, stated plainly rather than engineered around: a
compromise of the running host is a compromise of every seat's mailbox. Nothing
below removes that. What it does is make the database or disk alone worthless,
which is the realistic threat - a leaked backup, a snapshot, a stolen volume -
and keep plaintext out of logs and off disk.

ENVELOPE SCHEME. Each token is encrypted under a fresh 256-bit data key; that
data key is itself encrypted by a key-encrypting key (KEK) the process can use
but should never persist alongside the data. A KEK provider is an injected
dependency so a real deployment supplies a managed KMS, while tests and local
work supply a file-backed key. The wire format is versioned so the scheme can
be replaced without guessing what old records meant.

No primitive is implemented here. AES-256-GCM from `cryptography`, the same
library broker_crypto.py already depends on.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from private_runtime import atomic_write_json, ensure_private_directory


RECORD_VERSION = 1
DATA_KEY_BYTES = 32
NONCE_BYTES = 12


class TokenStoreError(RuntimeError):
    """Never carries plaintext, a key, or a path in its message."""


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(value):
    if not isinstance(value, str):
        raise TokenStoreError("token record field is not a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - base64 raises several types
        raise TokenStoreError("token record is not decodable") from exc


class FileKeyProvider:
    """Key-encrypting key held in a 0600 file beside nothing else.

    For local work and tests. A real deployment should pass a provider backed
    by a managed KMS instead, so the KEK is never material the host can read at
    rest - that is the whole difference between "a stolen disk is useless" and
    "a stolen disk is useless unless they also took the key file next to it".
    """

    def __init__(self, path):
        self.path = Path(path)

    def _load(self):
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise TokenStoreError(
                "key-encrypting key is unavailable"
            ) from exc
        if len(raw) != DATA_KEY_BYTES:
            raise TokenStoreError("key-encrypting key is the wrong size")
        return raw

    def create(self):
        """Generate a KEK once. Refuses to clobber an existing one."""
        ensure_private_directory(self.path.parent)
        descriptor = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(secrets.token_bytes(DATA_KEY_BYTES))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        return self

    def wrap(self, data_key, seat_id):
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = AESGCM(self._load()).encrypt(
            nonce, data_key, seat_id.encode("utf-8")
        )
        return nonce + sealed

    def unwrap(self, wrapped, seat_id):
        if len(wrapped) <= NONCE_BYTES:
            raise TokenStoreError("wrapped data key is malformed")
        nonce, sealed = wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:]
        try:
            return AESGCM(self._load()).decrypt(
                nonce, sealed, seat_id.encode("utf-8")
            )
        except InvalidTag as exc:
            raise TokenStoreError(
                "wrapped data key failed authentication"
            ) from exc


def token_path(connection):
    return connection.directory / "token.enc.json"


def store_token(connection, token_document, provider):
    """Encrypt and persist the connected account's token document.

    The connection id is bound into both AEAD layers as associated data, so a
    record copied from an archive or another deployment fails authentication
    instead of decrypting into the wrong mailbox.
    """
    if not isinstance(token_document, dict) or not token_document:
        raise TokenStoreError("token document must be a non-empty object")

    plaintext = json.dumps(
        token_document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    data_key = secrets.token_bytes(DATA_KEY_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(data_key).encrypt(
        nonce, plaintext, connection.id.encode("utf-8")
    )
    record = {
        "version": RECORD_VERSION,
        "seat": connection.id,
        "wrapped_key": _b64(provider.wrap(data_key, connection.id)),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    # Drop the plaintext key reference before the write can raise.
    data_key = None
    atomic_write_json(token_path(connection), record)
    return token_path(connection)


def load_token(connection, provider):
    """Decrypt the connected account's token document, or raise.

    The caller is expected to hold the result in memory for the duration of a
    run and drop it - never log it, never write it anywhere.
    """
    path = token_path(connection)
    try:
        with path.open(encoding="utf-8") as handle:
            record = json.load(handle)
    except OSError as exc:
        raise TokenStoreError("no stored token for this connection") from exc
    except json.JSONDecodeError as exc:
        raise TokenStoreError("token record is not valid JSON") from exc

    if not isinstance(record, dict):
        raise TokenStoreError("token record must be an object")
    if record.get("version") != RECORD_VERSION:
        raise TokenStoreError("token record has an unsupported version")
    if record.get("seat") != connection.id:
        raise TokenStoreError("token record belongs to a different seat")

    data_key = provider.unwrap(_unb64(record["wrapped_key"]), connection.id)
    try:
        plaintext = AESGCM(data_key).decrypt(
            _unb64(record["nonce"]), _unb64(record["ciphertext"]),
            connection.id.encode("utf-8"),
        )
    except InvalidTag as exc:
        raise TokenStoreError("token record failed authentication") from exc
    finally:
        data_key = None

    try:
        document = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenStoreError("decrypted token is not valid JSON") from exc
    if not isinstance(document, dict):
        raise TokenStoreError("decrypted token is not an object")
    return document


def forget_token(connection):
    """Delete the local record.

    Local deletion is NOT revocation. A caller disconnecting must also
    call Google's revocation endpoint, or the grant stays alive at Google and
    merely becomes invisible here. That call is deliberately not made from this
    module, which never contacts the network.
    """
    try:
        token_path(connection).unlink()
        return True
    except FileNotFoundError:
        return False
