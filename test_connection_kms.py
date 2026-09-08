"""Offline tests for the Cloud KMS key-encrypting-key provider.

Nothing here touches Google. The double implements real AES-GCM rather than
echoing its input, deliberately: a stub that ignored associated data would
make the binding test below pass whether or not the provider passed the seat
id, which is precisely the shadowed-guard failure this project keeps finding.
The double is a real AEAD, so the binding test fails if the provider stops
binding.
"""
import ast
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import connection as conn
import connection_kms as kms
import connection_tokens as tokens
from connection_kms import SCHEME, KmsKeyProvider, KmsProviderError


KEY = ("projects/example-project/locations/us-central1/"
       "keyRings/triage/cryptoKeys/connection-kek")
A = "coach@example.test"


class _Response:
    def __init__(self, **fields):
        for name, value in fields.items():
            setattr(self, name, value)


def reference_crc32c(data):
    """CRC-32C (Castagnoli), the algorithm Cloud KMS uses.

    Written out rather than imported so these tests need no dependency, and so
    the provider's real checksum can be compared against something computed
    independently of it. Verified below against the standard check vector.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


class FakeKms:
    """Cloud KMS's contract, not the happy path.

    THE POINT OF THIS CLASS. The previous version returned
    verified_plaintext_crc32c=True unconditionally, so a provider that sent no
    checksum at all looked identical to one that sent a correct one. Ten
    mutations passed against it and the first real call failed. The real
    service reports False when no checksum accompanied the request, because
    there was nothing to verify - so this does too, and that single line is
    what makes the checksum tests mean anything.
    """

    def __init__(self, key=None):
        self.key = key or secrets.token_bytes(32)
        self.encrypt_calls = []
        self.decrypt_calls = []

    @staticmethod
    def _verify(request, data_field, crc_field):
        """False when absent, exactly as the service reports it."""
        supplied = request.get(crc_field)
        if supplied is None:
            return False
        return int(supplied) == reference_crc32c(request.get(data_field) or b"")

    def encrypt(self, request, timeout=None):
        self.encrypt_calls.append((request, timeout))
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(self.key).encrypt(
            nonce, request["plaintext"],
            request.get("additional_authenticated_data") or b"",
        )
        ciphertext = nonce + sealed
        return _Response(
            ciphertext=ciphertext,
            ciphertext_crc32c=reference_crc32c(ciphertext),
            verified_plaintext_crc32c=self._verify(
                request, "plaintext", "plaintext_crc32c"),
            verified_additional_authenticated_data_crc32c=self._verify(
                request, "additional_authenticated_data",
                "additional_authenticated_data_crc32c"),
        )

    def decrypt(self, request, timeout=None):
        self.decrypt_calls.append((request, timeout))
        # The real service rejects a request whose checksum disagrees with its
        # payload outright, rather than reporting it in the response.
        if not self._verify(request, "ciphertext", "ciphertext_crc32c"):
            raise ValueError("INVALID_ARGUMENT: ciphertext checksum mismatch")
        blob = request["ciphertext"]
        plaintext = AESGCM(self.key).decrypt(
            blob[:12], blob[12:],
            request.get("additional_authenticated_data") or b"",
        )
        return _Response(plaintext=plaintext,
                         plaintext_crc32c=reference_crc32c(plaintext))


class BrokenKms:
    def encrypt(self, request, timeout=None):
        raise RuntimeError(
            f"permission denied on {request['name']} for caller@project"
        )

    def decrypt(self, request, timeout=None):
        raise RuntimeError(
            f"permission denied on {request['name']} for caller@project"
        )


def _provider(client=None):
    return KmsKeyProvider(KEY, client or FakeKms(), crc32c=reference_crc32c)


# ---------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------

def test_a_data_key_survives_a_wrap_and_unwrap():
    provider = _provider()
    data_key = secrets.token_bytes(tokens.DATA_KEY_BYTES)
    assert provider.unwrap(provider.wrap(data_key, "active"), "active") == data_key


def test_the_wrapped_blob_never_contains_the_data_key():
    provider = _provider()
    data_key = secrets.token_bytes(tokens.DATA_KEY_BYTES)
    assert data_key not in provider.wrap(data_key, "active")


def test_the_key_name_is_sent_on_every_call():
    client = FakeKms()
    provider = KmsKeyProvider(KEY, client, crc32c=reference_crc32c)
    provider.unwrap(provider.wrap(b"k" * 32, "active"), "active")
    assert client.encrypt_calls[0][0]["name"] == KEY
    assert client.decrypt_calls[0][0]["name"] == KEY


def test_a_timeout_is_always_passed_so_a_hung_call_cannot_hang_a_run():
    client = FakeKms()
    provider = KmsKeyProvider(KEY, client, timeout=3,
                               crc32c=reference_crc32c)
    provider.unwrap(provider.wrap(b"k" * 32, "active"), "active")
    assert client.encrypt_calls[0][1] == 3
    assert client.decrypt_calls[0][1] == 3


# ---------------------------------------------------------------------
# The seat binding
# ---------------------------------------------------------------------

def test_the_seat_id_is_bound_so_a_blob_cannot_move_between_connections():
    """The double is a real AEAD, so this fails if binding is dropped."""
    provider = _provider()
    wrapped = provider.wrap(b"k" * 32, "active")
    with pytest.raises(KmsProviderError):
        provider.unwrap(wrapped, "some-other-connection")


def test_the_seat_id_actually_reaches_the_client_as_associated_data():
    client = FakeKms()
    KmsKeyProvider(KEY, client, crc32c=reference_crc32c).wrap(b"k" * 32, "active")
    request = client.encrypt_calls[0][0]
    assert request["additional_authenticated_data"] == b"active"


# ---------------------------------------------------------------------
# Scheme tagging
# ---------------------------------------------------------------------

def test_a_wrapped_blob_declares_its_scheme():
    assert _provider().wrap(b"k" * 32, "active").startswith(SCHEME)


def test_a_file_provider_blob_is_refused_by_name_not_by_crypto_error(tmp_path):
    """The wrong-provider case must read as the wrong provider."""
    file_provider = tokens.FileKeyProvider(tmp_path / "kek").create()
    foreign = file_provider.wrap(b"k" * 32, "active")

    with pytest.raises(KmsProviderError) as caught:
        _provider().unwrap(foreign, "active")
    assert "different key provider" in str(caught.value)


def test_a_kms_blob_is_refused_by_the_file_provider_too(tmp_path):
    file_provider = tokens.FileKeyProvider(tmp_path / "kek").create()
    wrapped = _provider().wrap(b"k" * 32, "active")
    with pytest.raises(tokens.TokenStoreError):
        file_provider.unwrap(wrapped, "active")


# ---------------------------------------------------------------------
# It cannot provision
# ---------------------------------------------------------------------

def test_creating_a_key_is_refused():
    with pytest.raises(KmsProviderError) as caught:
        _provider().create()
    assert "provisioned by the operator" in str(caught.value)


def test_the_refusal_names_the_command_to_run_instead():
    with pytest.raises(KmsProviderError) as caught:
        _provider().create()
    assert "gcloud kms keys create" in str(caught.value)


def test_nothing_in_the_module_can_create_a_key():
    """AST, not string search: no call to any key-creation method exists."""
    tree = ast.parse(Path("connection_kms.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            assert "create_crypto_key" not in name
            assert "create_key_ring" not in name


# ---------------------------------------------------------------------
# Configuration failures happen at construction
# ---------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "", "   ", "not-a-key-name", "projects/p/locations/l/keyRings/r",
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/extra",
    "PROJECTS/p/locations/l/keyRings/r/cryptoKeys/k",
])
def test_a_malformed_key_name_is_refused_at_construction(bad):
    with pytest.raises(KmsProviderError):
        KmsKeyProvider(bad, FakeKms())


def test_a_wellformed_key_name_is_accepted():
    assert KmsKeyProvider(KEY, FakeKms()).key_name == KEY


def test_a_missing_client_is_refused_for_being_missing():
    """Asserting the reason, not just the refusal.

    Without the specific message this test passes even with the None branch
    deleted, because getattr(None, "encrypt") is also not callable and the
    next check refuses it anyway - a shadowed guard. The two cases are
    different faults (an unset variable versus the wrong object) and deserve
    to read differently.
    """
    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, None)
    assert "must be supplied" in str(caught.value)


def test_a_client_missing_a_method_is_refused_before_any_token_exists():
    class Half:
        def encrypt(self, request, timeout=None):
            return None

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, Half())
    assert "decrypt" in str(caught.value)


# ---------------------------------------------------------------------
# Failure messages leak nothing
# ---------------------------------------------------------------------

def test_a_client_error_is_reported_without_its_message():
    """A KMS error string quotes the resource name and the caller identity."""
    provider = KmsKeyProvider(KEY, BrokenKms(), crc32c=reference_crc32c)
    with pytest.raises(KmsProviderError) as caught:
        provider.wrap(b"k" * 32, "active")

    message = str(caught.value)
    assert "RuntimeError" in message
    assert "permission denied" not in message
    assert "caller@project" not in message
    assert KEY not in message


def test_no_failure_message_carries_the_key_name():
    provider = KmsKeyProvider(KEY, BrokenKms(), crc32c=reference_crc32c)
    for call in (lambda: provider.wrap(b"k" * 32, "active"),
                 lambda: provider.unwrap(SCHEME + b"\x00ct", "active")):
        with pytest.raises(KmsProviderError) as caught:
            call()
        assert KEY not in str(caught.value)
        assert "triage" not in str(caught.value)


def test_a_kms_error_is_catchable_as_a_token_store_error():
    """Callers already handling token storage need no new except clause."""
    provider = KmsKeyProvider(KEY, BrokenKms(), crc32c=reference_crc32c)
    with pytest.raises(tokens.TokenStoreError):
        provider.wrap(b"k" * 32, "active")


# ---------------------------------------------------------------------
# Malformed responses
# ---------------------------------------------------------------------

def test_an_empty_ciphertext_response_is_refused():
    class Empty(FakeKms):
        def encrypt(self, request, timeout=None):
            return _Response(ciphertext=b"")

    with pytest.raises(KmsProviderError):
        KmsKeyProvider(KEY, Empty(), crc32c=reference_crc32c).wrap(b"k" * 32, "active")


def test_an_unverified_plaintext_checksum_is_refused():
    """Well-formed in every other respect, so only this check can fire.

    The earlier version of this test built a response that was ALSO missing
    ciphertext_crc32c, so deleting the verified check simply moved the failure
    to the next one and the mutation escaped. Deriving the response from the
    working double and flipping one field isolates it.
    """
    class Unverified(FakeKms):
        def encrypt(self, request, timeout=None):
            response = super().encrypt(request, timeout)
            response.verified_plaintext_crc32c = False
            return response

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, Unverified(),
                       crc32c=reference_crc32c).wrap(b"k" * 32, "active")
    assert "did not confirm the data key checksum" in str(caught.value)


def test_an_unverified_associated_data_checksum_is_refused():
    """Corrupted AAD would surface much later, as a failed unwrap."""
    class UnverifiedAad(FakeKms):
        def encrypt(self, request, timeout=None):
            response = super().encrypt(request, timeout)
            response.verified_additional_authenticated_data_crc32c = False
            return response

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, UnverifiedAad(),
                       crc32c=reference_crc32c).wrap(b"k" * 32, "active")
    assert "connection id checksum" in str(caught.value)


def test_a_tampered_decrypt_response_is_refused():
    """The data key coming back corrupted, which no verified flag reports."""
    class TamperedPlaintext(FakeKms):
        def decrypt(self, request, timeout=None):
            response = super().decrypt(request, timeout)
            response.plaintext_crc32c = reference_crc32c(b"different bytes")
            return response

    provider = KmsKeyProvider(KEY, TamperedPlaintext(),
                              crc32c=reference_crc32c)
    wrapped = provider.wrap(b"k" * 32, "active")
    with pytest.raises(KmsProviderError) as caught:
        provider.unwrap(wrapped, "active")
    assert "corrupted in transit" in str(caught.value)


def test_a_decrypt_response_with_no_checksum_is_refused():
    class NoPlaintextCrc(FakeKms):
        def decrypt(self, request, timeout=None):
            response = super().decrypt(request, timeout)
            del response.plaintext_crc32c
            return response

    provider = KmsKeyProvider(KEY, NoPlaintextCrc(), crc32c=reference_crc32c)
    wrapped = provider.wrap(b"k" * 32, "active")
    with pytest.raises(KmsProviderError) as caught:
        provider.unwrap(wrapped, "active")
    assert "cannot be checked" in str(caught.value)


def test_a_missing_verified_field_fails_closed():
    """This test previously asserted the exact opposite, and that was the bug.

    It read "a missing field is an older client, not a failed verification"
    and let the absent flag pass. Combined with a provider that sent no
    checksum, it meant nothing anywhere in the suite could distinguish
    "verified" from "never asked". Now that every request carries a checksum,
    a response that does not confirm it is a response we cannot trust.
    """
    class NoField:
        def encrypt(self, request, timeout=None):
            return _Response(ciphertext=b"x" * 40)

        def decrypt(self, request, timeout=None):
            return _Response(plaintext=b"k" * 32)

    provider = KmsKeyProvider(KEY, NoField(), crc32c=reference_crc32c)
    with pytest.raises(KmsProviderError) as caught:
        provider.wrap(b"k" * 32, "active")
    assert "did not confirm" in str(caught.value)


def test_a_response_checksum_that_disagrees_is_refused():
    """Corruption on the way back, which the verified flag cannot catch."""
    class Tampered(FakeKms):
        def encrypt(self, request, timeout=None):
            response = super().encrypt(request, timeout)
            response.ciphertext_crc32c = reference_crc32c(b"different bytes")
            return response

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, Tampered(),
                       crc32c=reference_crc32c).wrap(b"k" * 32, "active")
    assert "corrupted in transit" in str(caught.value)


def test_a_missing_response_checksum_is_refused():
    class NoCiphertextCrc(FakeKms):
        def encrypt(self, request, timeout=None):
            response = super().encrypt(request, timeout)
            del response.ciphertext_crc32c
            return response

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, NoCiphertextCrc(),
                       crc32c=reference_crc32c).wrap(b"k" * 32, "active")
    assert "cannot be checked" in str(caught.value)


def test_a_wrong_sized_data_key_is_refused_rather_than_used_as_an_aes_key():
    class Short(FakeKms):
        def decrypt(self, request, timeout=None):
            # A correct checksum for the wrong-sized key, so this reaches the
            # size check rather than tripping the corruption check first.
            return _Response(plaintext=b"too-short",
                             plaintext_crc32c=reference_crc32c(b"too-short"))

    provider = KmsKeyProvider(KEY, Short(), crc32c=reference_crc32c)
    wrapped = provider.wrap(b"k" * 32, "active")
    with pytest.raises(KmsProviderError) as caught:
        provider.unwrap(wrapped, "active")
    assert "wrong size" in str(caught.value)


@pytest.mark.parametrize("bad", [b"", None, "a string", SCHEME, SCHEME + b"\x00"])
def test_a_malformed_wrapped_blob_is_refused(bad):
    with pytest.raises(KmsProviderError):
        _provider().unwrap(bad, "active")


# ---------------------------------------------------------------------
# It works where it actually gets used
# ---------------------------------------------------------------------

def test_a_token_stored_under_kms_loads_back_unchanged(tmp_path):
    connection = conn.connect(tmp_path, A)
    provider = _provider()
    document = {"refresh_token": "r" * 40, "client_id": "c", "scopes": ["s"]}

    tokens.store_token(connection, document, provider)
    assert tokens.load_token(connection, provider) == document


def test_the_stored_record_holds_no_plaintext_token(tmp_path):
    connection = conn.connect(tmp_path, A)
    provider = _provider()
    tokens.store_token(connection, {"refresh_token": "SECRET-VALUE"}, provider)

    raw = tokens.token_path(connection).read_text(encoding="utf-8")
    assert "SECRET-VALUE" not in raw
    assert "refresh_token" not in raw


def test_a_record_wrapped_under_one_kms_key_fails_under_another(tmp_path):
    """A copied deployment cannot open the original's token."""
    connection = conn.connect(tmp_path, A)
    tokens.store_token(connection, {"refresh_token": "r"}, _provider())

    other = KmsKeyProvider(KEY, FakeKms(key=secrets.token_bytes(32)),
                           crc32c=reference_crc32c)
    with pytest.raises(tokens.TokenStoreError):
        tokens.load_token(connection, other)


# ---------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------

def test_the_module_imports_no_google_library_and_opens_no_connection():
    tree = ast.parse(Path("connection_kms.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("google", "googleapiclient", "grpc", "requests",
                      "urllib", "socket", "http", "subprocess"):
        assert forbidden not in imported, (
            f"connection_kms imports {forbidden}; the client is injected so "
            "this module stays importable with no credentials"
        )


def test_the_module_is_importable_with_no_credentials_present():
    """A fresh interpreter, not importlib.reload.

    Reloading rebinds the module's classes, so a KmsProviderError raised
    afterwards is a DIFFERENT class from the one imported at the top of this
    file - which silently broke a later pytest.raises and made that test fail
    only when the whole file ran in order. A subprocess proves the real thing
    (the module imports with nothing Google installed) and leaves this
    interpreter's module registry alone.
    """
    import os
    import subprocess
    import sys

    environment = {k: v for k, v in os.environ.items()
                   if k != "GOOGLE_APPLICATION_CREDENTIALS"}
    result = subprocess.run(
        [sys.executable, "-c",
         "import connection_kms; print(connection_kms.SCHEME.decode())"],
        capture_output=True, text=True, env=environment,
        cwd=str(Path(__file__).parent),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "kms1"


# ---------------------------------------------------------------------
# The request actually carries the checksums
#
# This section is the regression. The provider previously read
# verified_plaintext_crc32c without ever sending plaintext_crc32c, and every
# test passed because the double answered True regardless. These assert the
# request shape directly, so the omission cannot come back silently.
# ---------------------------------------------------------------------

def test_the_encrypt_request_carries_a_checksum_of_the_data_key():
    client = FakeKms()
    data_key = secrets.token_bytes(32)
    KmsKeyProvider(KEY, client, crc32c=reference_crc32c).wrap(data_key, "active")

    request = client.encrypt_calls[0][0]
    assert "plaintext_crc32c" in request, (
        "no checksum was sent; KMS answers verified_plaintext_crc32c=False "
        "when there is nothing to verify, and every real call fails"
    )
    assert request["plaintext_crc32c"] == reference_crc32c(data_key)


def test_the_encrypt_request_carries_a_checksum_of_the_associated_data():
    client = FakeKms()
    KmsKeyProvider(KEY, client, crc32c=reference_crc32c).wrap(b"k" * 32, "active")

    request = client.encrypt_calls[0][0]
    assert request["additional_authenticated_data_crc32c"] == \
        reference_crc32c(b"active")


def test_the_decrypt_request_carries_a_checksum_of_the_ciphertext():
    client = FakeKms()
    provider = KmsKeyProvider(KEY, client, crc32c=reference_crc32c)
    provider.unwrap(provider.wrap(b"k" * 32, "active"), "active")

    request = client.decrypt_calls[0][0]
    assert "ciphertext_crc32c" in request
    assert request["ciphertext_crc32c"] == reference_crc32c(request["ciphertext"])


def test_a_provider_that_sent_no_checksum_would_be_rejected_by_the_double():
    """The double models the contract, so this failure is reproducible here.

    Without this the suite could only prove what the provider sends, not that
    sending nothing is fatal - which is the shape the real failure took.
    """
    client = FakeKms()
    response = client.encrypt({"name": KEY, "plaintext": b"k" * 32,
                               "additional_authenticated_data": b"active"})
    assert response.verified_plaintext_crc32c is False


def test_the_double_confirms_a_correct_checksum():
    """The other half, so the check above is not passing for a stale reason."""
    client = FakeKms()
    response = client.encrypt({
        "name": KEY, "plaintext": b"k" * 32,
        "plaintext_crc32c": reference_crc32c(b"k" * 32),
        "additional_authenticated_data": b"active",
        "additional_authenticated_data_crc32c": reference_crc32c(b"active"),
    })
    assert response.verified_plaintext_crc32c is True
    assert response.verified_additional_authenticated_data_crc32c is True


def test_a_wrong_checksum_is_not_confirmed():
    client = FakeKms()
    response = client.encrypt({
        "name": KEY, "plaintext": b"k" * 32,
        "plaintext_crc32c": reference_crc32c(b"different"),
        "additional_authenticated_data": b"active",
    })
    assert response.verified_plaintext_crc32c is False


# ---------------------------------------------------------------------
# The default checksum implementation
# ---------------------------------------------------------------------

def test_the_reference_matches_the_standard_crc32c_check_vector():
    """0xE3069283 for "123456789" is the published CRC-32C check value.

    Without this the reference could be any self-consistent hash and every
    test above would still pass while the deployment sent checksums Google
    rejects.
    """
    assert reference_crc32c(b"123456789") == 0xE3069283


def test_the_default_implementation_is_google_crc32c_or_a_clear_failure():
    """Whichever the host has, the behaviour is defined.

    Installed: it must agree with the reference on the check vector.
    Absent: it must fail loudly, because silently skipping the checksum is the
    original bug wearing a different hat.
    """
    try:
        import google_crc32c  # noqa: F401
    except ImportError:
        with pytest.raises(KmsProviderError) as caught:
            kms.default_crc32c(b"123456789")
        assert "google-crc32c is not installed" in str(caught.value)
        return
    assert kms.default_crc32c(b"123456789") == 0xE3069283
    assert kms.default_crc32c(b"active") == reference_crc32c(b"active")


def test_the_provider_defaults_to_the_real_implementation():
    """No silent fallback: an un-injected provider uses google-crc32c."""
    assert KmsKeyProvider(KEY, FakeKms()).crc32c is kms.default_crc32c
