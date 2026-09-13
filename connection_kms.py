"""Cloud KMS provider for wrapping envelope-encryption data keys.

The KMS key remains managed by Google. Requests and responses use CRC32C
integrity checks, and the client is injected so offline tests need no network
or cloud credentials.
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
    """KMS failure whose message excludes data and key identifiers."""


def _require_bytes(value, label):
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise KmsProviderError(f"{label} must be non-empty bytes")
    return bytes(value)


def default_crc32c(data):
    """CRC32C of `data`, from google-crc32c.

    Imported here rather than at module scope for the same reason the KMS
    client is injected: this module must stay importable with nothing Google
    installed. Missing the library is a hard failure rather than a silent
    downgrade - skipping the checksum is exactly the bug this function exists
    to fix, and doing it quietly would hide the same failure a second time.
    """
    try:
        import google_crc32c  # noqa: PLC0415 - deliberately deferred
    except ImportError as exc:
        raise KmsProviderError(
            "google-crc32c is not installed; it is required to checksum "
            "requests to Cloud KMS. Install it on the deployment host"
        ) from exc
    return int(google_crc32c.value(data))


def _require_verified(verified, field, label):
    """Insist the service confirmed the checksum we sent for `label`.

    Takes the VALUE, not the field name: the no-send audit refuses a computed
    getattr in production code, and rightly - an attribute name assembled at
    runtime cannot be statically audited. Callers read the field with a
    literal name and pass what they got.

    Fails closed on a missing field. Earlier this defaulted to "assume
    verified" so a minimal test double would pass, which is precisely how a
    request that carried no checksum at all went unnoticed: the real service
    answered False, every double answered True, and nothing in between was
    ever exercised.
    """
    if verified is not True:
        raise KmsProviderError(
            f"KMS did not confirm the {label} checksum ({field}={verified!r}); "
            "the request may have been corrupted in transit, or may have "
            "carried no checksum to verify"
        )


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

    def __init__(self, key_name, client, *, timeout=DEFAULT_TIMEOUT_SECONDS,
                 crc32c=None):
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
        # Injected like the client, so tests exercise the real request shape
        # against a reference implementation without needing the library.
        self.crc32c = crc32c or default_crc32c

    def _require_matching_crc(self, reported, field, data, label):
        """Insist the bytes we received match the checksum sent with them.

        Takes the reported value rather than the field name, for the same
        reason _require_verified does.
        """
        if reported is None:
            raise KmsProviderError(
                f"KMS returned no {field}; the {label} cannot be checked for "
                "corruption in transit"
            )
        if int(reported) != self.crc32c(data):
            raise KmsProviderError(
                f"the {label} returned by KMS does not match its checksum; "
                "it was corrupted in transit"
            )

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
        associated = seat_id.encode("utf-8")
        response = self._call(self.client.encrypt, {
            "name": self.key_name,
            "plaintext": data_key,
            "plaintext_crc32c": self.crc32c(data_key),
            "additional_authenticated_data": associated,
            "additional_authenticated_data_crc32c": self.crc32c(associated),
        })
        ciphertext = getattr(response, "ciphertext", None)
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise KmsProviderError("KMS returned no ciphertext")

        # Outbound integrity: the server confirms the checksum it received
        # matches the bytes it received. This is only meaningful because the
        # request above actually carries plaintext_crc32c - KMS reports False
        # when no checksum was sent, since there was nothing to verify.
        _require_verified(
            getattr(response, "verified_plaintext_crc32c", None),
            "verified_plaintext_crc32c", "data key")
        _require_verified(
            getattr(response, "verified_additional_authenticated_data_crc32c",
                    None),
            "verified_additional_authenticated_data_crc32c", "connection id")

        # Inbound integrity: we confirm the ciphertext arrived intact.
        self._require_matching_crc(
            getattr(response, "ciphertext_crc32c", None),
            "ciphertext_crc32c", ciphertext, "ciphertext")
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

        associated = seat_id.encode("utf-8")
        response = self._call(self.client.decrypt, {
            "name": self.key_name,
            "ciphertext": ciphertext,
            "ciphertext_crc32c": self.crc32c(ciphertext),
            "additional_authenticated_data": associated,
            "additional_authenticated_data_crc32c": self.crc32c(associated),
        })
        plaintext = getattr(response, "plaintext", None)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise KmsProviderError("KMS returned no plaintext")
        plaintext = bytes(plaintext)

        # DecryptResponse carries no "verified" flag - a corrupted request is
        # rejected outright by the service - so the only check available here
        # is that the plaintext came back intact.
        self._require_matching_crc(
            getattr(response, "plaintext_crc32c", None),
            "plaintext_crc32c", plaintext, "data key")

        # A data key of the wrong length would be used as an AES key and fail
        # somewhere less obvious. Refuse here, where the cause is visible.
        if len(plaintext) != DATA_KEY_BYTES:
            raise KmsProviderError("unwrapped data key is the wrong size")
        return plaintext
