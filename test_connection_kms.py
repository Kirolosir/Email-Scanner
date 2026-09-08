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


class FakeKms:
    """A real AEAD standing in for Cloud KMS.

    Holds the key that Cloud KMS would hold, so associated data, ciphertext
    integrity and cross-key rejection all behave as the real service behaves.
    """

    def __init__(self, key=None):
        self.key = key or secrets.token_bytes(32)
        self.encrypt_calls = []
        self.decrypt_calls = []

    def encrypt(self, request, timeout=None):
        self.encrypt_calls.append((request, timeout))
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(self.key).encrypt(
            nonce, request["plaintext"],
            request.get("additional_authenticated_data") or b"",
        )
        return _Response(ciphertext=nonce + sealed,
                         verified_plaintext_crc32c=True)

    def decrypt(self, request, timeout=None):
        self.decrypt_calls.append((request, timeout))
        blob = request["ciphertext"]
        plaintext = AESGCM(self.key).decrypt(
            blob[:12], blob[12:],
            request.get("additional_authenticated_data") or b"",
        )
        return _Response(plaintext=plaintext)


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
    return KmsKeyProvider(KEY, client or FakeKms())


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
    provider = KmsKeyProvider(KEY, client)
    provider.unwrap(provider.wrap(b"k" * 32, "active"), "active")
    assert client.encrypt_calls[0][0]["name"] == KEY
    assert client.decrypt_calls[0][0]["name"] == KEY


def test_a_timeout_is_always_passed_so_a_hung_call_cannot_hang_a_run():
    client = FakeKms()
    provider = KmsKeyProvider(KEY, client, timeout=3)
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
    KmsKeyProvider(KEY, client).wrap(b"k" * 32, "active")
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
    provider = KmsKeyProvider(KEY, BrokenKms())
    with pytest.raises(KmsProviderError) as caught:
        provider.wrap(b"k" * 32, "active")

    message = str(caught.value)
    assert "RuntimeError" in message
    assert "permission denied" not in message
    assert "caller@project" not in message
    assert KEY not in message


def test_no_failure_message_carries_the_key_name():
    provider = KmsKeyProvider(KEY, BrokenKms())
    for call in (lambda: provider.wrap(b"k" * 32, "active"),
                 lambda: provider.unwrap(SCHEME + b"\x00ct", "active")):
        with pytest.raises(KmsProviderError) as caught:
            call()
        assert KEY not in str(caught.value)
        assert "triage" not in str(caught.value)


def test_a_kms_error_is_catchable_as_a_token_store_error():
    """Callers already handling token storage need no new except clause."""
    provider = KmsKeyProvider(KEY, BrokenKms())
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
        KmsKeyProvider(KEY, Empty()).wrap(b"k" * 32, "active")


def test_an_unverified_checksum_is_refused():
    class Unverified(FakeKms):
        def encrypt(self, request, timeout=None):
            return _Response(ciphertext=b"x" * 40,
                             verified_plaintext_crc32c=False)

    with pytest.raises(KmsProviderError) as caught:
        KmsKeyProvider(KEY, Unverified()).wrap(b"k" * 32, "active")
    assert "checksum" in str(caught.value)


def test_a_client_without_the_checksum_field_is_not_treated_as_a_failure():
    """A missing field is an older client, not a failed verification."""
    class NoField:
        def encrypt(self, request, timeout=None):
            return _Response(ciphertext=b"x" * 40)

        def decrypt(self, request, timeout=None):
            return _Response(plaintext=b"k" * 32)

    provider = KmsKeyProvider(KEY, NoField())
    assert provider.wrap(b"k" * 32, "active").startswith(SCHEME)


def test_a_wrong_sized_data_key_is_refused_rather_than_used_as_an_aes_key():
    class Short(FakeKms):
        def decrypt(self, request, timeout=None):
            return _Response(plaintext=b"too-short")

    provider = KmsKeyProvider(KEY, Short())
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

    other = KmsKeyProvider(KEY, FakeKms(key=secrets.token_bytes(32)))
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


def test_the_module_is_importable_with_no_credentials_present(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    importlib = __import__("importlib")
    importlib.reload(kms)
    assert kms.SCHEME == b"kms1"
