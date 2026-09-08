"""Cloud KMS as the key-encrypting key, so the host never holds key material.

FileKeyProvider keeps the KEK in a 0600 file beside the data it protects, and
connection_tokens.py says exactly what that is worth: "a stolen disk is useless
unless they also took the key file next to it". This provider closes that gap.
The KEK lives in Cloud KMS and never leaves it. The host holds an IAM
permission to call encrypt and decrypt, not the key.

What that buys, and what it does not:

  * A stolen disk, snapshot or backup yields ciphertext and nothing else,
    because the material needed to unwrap it was never on the disk.
  * A compromise of the RUNNING host still reaches the mailbox, because a
    process that may call decrypt can decrypt. connection_tokens.py states
    this about the scheme as a whole and it remains true here. Nothing below
    pretends otherwise.

The gain is specifically against offline theft of storage, which is the
realistic threat, and every unwrap becomes a Cloud Audit Log entry, which a
local key file could never provide.

THE CLIENT IS INJECTED. This module imports no Google library and opens no
connection at import time, so it stays importable in CI with no credentials
and its tests stay offline. That is the same shape connection_archive.py uses
for revocation, for the same reason.

IT CANNOT CREATE A KEY. create() refuses, permanently. Provisioning a key ring
and a key has IAM consequences and a billing footprint; it belongs to the
operator at a terminal, not to a web process that happened to boot holding
credentials. The refusal carries the command to run instead.
"""
from __future__ import annotations

import re

from connection_tokens import DATA_KEY_BYTES, TokenStoreError


# A wrapped blob records the scheme that produced it. Without this, a record
# wrapped by FileKeyProvider and handed to this provider would fail somewhere
# inside a Google library with a message about ciphertext, sending whoever is
# reading the logs to look at the wrong thing entirely.
SCHEME = b"kms1"
SEPARATOR = b"\x00"

# projects/P/locations/L/keyRings/R/cryptoKeys/K - checked at construction so
# a typo in an environment variable fails at boot, not at 6pm on the first
# token load of a real run.
KEY_NAME = re.compile(
    r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$"
)

DEFAULT_TIMEOUT_SECONDS = 20


class KmsProviderError(TokenStoreError):
    """A KMS-specific failure.

    Inherits TokenStoreError so callers that already handle token storage
    failures need no new except clause, and inherits its contract too: the
    message never carries plaintext, key material, or the key's resource name.
    A resource name is not a secret, but it names the project and key ring to
    anyone reading a log, and there is nothing a caller can do with it that
    they could not do by reading the deployment's own configuration.
    """


def _require_bytes(value, label):
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise KmsProviderError(f"{label} must be non-empty bytes")
    return bytes(value)


class KmsKeyProvider:
    """Wrap and unwrap data keys with a Cloud KMS symmetric key.

    `client` is any object exposing the two methods
    google.cloud.kms.KeyManagementServiceClient exposes:

        client.encrypt(request={"name", "plaintext",
                                "additional_authenticated_data"}, timeout=...)
        client.decrypt(request={"name", "ciphertext",
                                "additional_authenticated_data"}, timeout=...)

    returning objects carrying `.ciphertext` and `.plaintext`. Nothing here
    constructs one; a deployment builds it and passes it in.
    """

    def __init__(self, key_name, client, *, timeout=DEFAULT_TIMEOUT_SECONDS):
        if not isinstance(key_name, str) or not KEY_NAME.match(key_name.strip()):
            raise KmsProviderError(
                "KMS key name must look like projects/P/locations/L/"
                "keyRings/R/cryptoKeys/K"
            )
        if client is None:
            raise KmsProviderError("a KMS client must be supplied")
        # Named one at a time rather than looped. A computed attribute name is
        # not statically auditable, and the no-send audit rightly refuses to
        # let production code reach an attribute it cannot name.
        if not callable(getattr(client, "encrypt", None)):
            raise KmsProviderError("KMS client does not provide encrypt()")
        if not callable(getattr(client, "decrypt", None)):
            raise KmsProviderError("KMS client does not provide decrypt()")
        self.key_name = key_name.strip()
        self.client = client
        self.timeout = timeout

    # -- provisioning is not ours to do ---------------------------------

    def create(self):
        """Refuse, and say what to run instead.

        FileKeyProvider.create() generates a key because a local file is a
        local concern. A KMS key is not: creating one touches IAM, billing and
        an audit trail on a real cloud account. A process that can create the
        key it will later use to decrypt mailbox tokens is a process that can
        bootstrap itself out of any review, so this path does not exist.
        """
        raise KmsProviderError(
            "a Cloud KMS key is provisioned by the operator, not by this "
            "process. Create it once with: gcloud kms keys create <KEY> "
            "--location <LOCATION> --keyring <RING> --purpose encryption"
        )

    # -- the provider interface -----------------------------------------

    def _call(self, method, request):
        try:
            return method(request=request, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 - any client/transport error
            # The exception type alone. A KMS error string can quote the
            # resource name and, on some transports, the request payload.
            raise KmsProviderError(
                f"KMS call failed ({type(exc).__name__})"
            ) from exc

    def wrap(self, data_key, seat_id):
        data_key = _require_bytes(data_key, "data key")
        response = self._call(self.client.encrypt, {
            "name": self.key_name,
            "plaintext": data_key,
            "additional_authenticated_data": seat_id.encode("utf-8"),
        })
        ciphertext = getattr(response, "ciphertext", None)
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise KmsProviderError("KMS returned no ciphertext")

        # KMS reports whether it verified the checksum of what it received.
        # Present only on the real client; absent on a minimal double, and a
        # missing field is not a failed check.
        if getattr(response, "verified_plaintext_crc32c", True) is False:
            raise KmsProviderError(
                "KMS did not verify the request checksum; the data key may "
                "have been corrupted in transit"
            )
        return SCHEME + SEPARATOR + bytes(ciphertext)

    def unwrap(self, wrapped, seat_id):
        wrapped = _require_bytes(wrapped, "wrapped data key")
        prefix = SCHEME + SEPARATOR
        if not wrapped.startswith(prefix):
            raise KmsProviderError(
                "wrapped data key was not produced by the KMS provider; the "
                "record belongs to a different key provider"
            )
        ciphertext = wrapped[len(prefix):]
        if not ciphertext:
            raise KmsProviderError("wrapped data key is malformed")

        response = self._call(self.client.decrypt, {
            "name": self.key_name,
            "ciphertext": ciphertext,
            "additional_authenticated_data": seat_id.encode("utf-8"),
        })
        plaintext = getattr(response, "plaintext", None)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise KmsProviderError("KMS returned no plaintext")
        plaintext = bytes(plaintext)
        # A data key of the wrong length would be used as an AES key and fail
        # somewhere less obvious. Refuse here, where the cause is visible.
        if len(plaintext) != DATA_KEY_BYTES:
            raise KmsProviderError("unwrapped data key is the wrong size")
        return plaintext
