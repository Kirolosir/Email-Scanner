"""Envelope encryption for OAuth credentials stored with a mailbox row."""
from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from connection_tokens import DATA_KEY_BYTES, NONCE_BYTES, TokenStoreError


@dataclass(frozen=True)
class EncryptedMailboxToken:
    version: int
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


def _mailbox_aad(mailbox_id):
    try:
        return str(uuid.UUID(str(mailbox_id))).encode("ascii")
    except (ValueError, TypeError, AttributeError) as exc:
        raise TokenStoreError("mailbox id is invalid") from exc


def seal_mailbox_token(mailbox_id, token_document, provider):
    if not isinstance(token_document, dict) or not token_document:
        raise TokenStoreError("token document must be a non-empty object")
    aad = _mailbox_aad(mailbox_id)
    plaintext = json.dumps(
        token_document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    data_key = secrets.token_bytes(DATA_KEY_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    try:
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        wrapped_key = provider.wrap(data_key, aad.decode("ascii"))
        return EncryptedMailboxToken(1, wrapped_key, nonce, ciphertext)
    finally:
        data_key = None


def open_mailbox_token(mailbox_id, record, provider):
    if not isinstance(record, EncryptedMailboxToken) or record.version != 1:
        raise TokenStoreError("token record has an unsupported version")
    aad = _mailbox_aad(mailbox_id)
    data_key = provider.unwrap(record.wrapped_key, aad.decode("ascii"))
    try:
        plaintext = AESGCM(data_key).decrypt(
            record.nonce, record.ciphertext, aad
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

