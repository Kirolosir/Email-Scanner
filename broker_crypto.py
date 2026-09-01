"""Sealed-box encryption for tokens in transit through the OAuth broker.

The broker must hand a refresh token back to the operator without ever
holding something usable at rest. It seals the token to a public key the
operator generated on their own machine, so:

  * the broker can encrypt but cannot decrypt - it holds only a public key
  * a stolen broker disk yields ciphertext, not a Gmail token
  * the operator's private key never leaves their machine

Construction is X25519 -> HKDF-SHA256 -> AES-256-GCM, all from `cryptography`.
No primitive is implemented here; this module only composes them. The
ephemeral public key and the recipient public key are bound into both the
HKDF info and the AEAD associated data, so a sealed blob cannot be replayed
against a different recipient.

Wire format:  ephemeral_public(32) || nonce(12) || ciphertext+tag
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32
NONCE_BYTES = 12
HKDF_INFO_PREFIX = b"example-oauth-broker-seal-v1"
MIN_SEALED_LENGTH = KEY_BYTES + NONCE_BYTES + 16  # 16 = GCM tag


class SealError(ValueError):
    """Raised when a sealed blob is malformed or fails authentication."""


def generate_operator_keypair():
    """Create the operator's keypair. Run on the operator's machine only.

    Returns (private_bytes, public_bytes). The private half must never be
    given to the broker.
    """
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes_raw(),
        private.public_key().public_bytes_raw(),
    )


def _derive(shared, ephemeral_public, recipient_public):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=HKDF_INFO_PREFIX + ephemeral_public + recipient_public,
    ).derive(shared)


def seal(recipient_public, plaintext):
    """Encrypt plaintext to a recipient public key."""
    if not isinstance(recipient_public, (bytes, bytearray)) or \
            len(recipient_public) != KEY_BYTES:
        raise SealError("recipient public key must be 32 raw bytes")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if not plaintext:
        raise SealError("refusing to seal empty plaintext")

    recipient_public = bytes(recipient_public)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))

    key = _derive(shared, ephemeral_public, recipient_public)
    nonce = os.urandom(NONCE_BYTES)
    associated = ephemeral_public + recipient_public
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated)
    return ephemeral_public + nonce + ciphertext


def unseal(recipient_private, sealed):
    """Decrypt a sealed blob. Run on the operator's machine only."""
    if not isinstance(recipient_private, (bytes, bytearray)) or \
            len(recipient_private) != KEY_BYTES:
        raise SealError("recipient private key must be 32 raw bytes")
    sealed = bytes(sealed or b"")
    if len(sealed) < MIN_SEALED_LENGTH:
        raise SealError("sealed blob is truncated")

    ephemeral_public = sealed[:KEY_BYTES]
    nonce = sealed[KEY_BYTES:KEY_BYTES + NONCE_BYTES]
    ciphertext = sealed[KEY_BYTES + NONCE_BYTES:]

    private = X25519PrivateKey.from_private_bytes(bytes(recipient_private))
    recipient_public = private.public_key().public_bytes_raw()
    try:
        shared = private.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_public)
        )
        key = _derive(shared, ephemeral_public, recipient_public)
        associated = ephemeral_public + recipient_public
        return AESGCM(key).decrypt(nonce, ciphertext, associated)
    except Exception as exc:  # authentication failure, bad key, bad bytes
        raise SealError("sealed blob failed authentication") from exc
