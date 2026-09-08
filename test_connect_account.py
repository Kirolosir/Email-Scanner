"""Offline tests for wiring a collected credential into the connection.

Nothing here reaches Google. The KMS client is a double built on real AES-GCM,
for the reason test_connection_kms.py gives: a stub that ignored associated
data would let the binding survive being deleted.

The properties:

  W1  importing or running this never constructs a real KMS client
  W2  a refusal writes nothing - no record, no token, no deleted credential
  W3  the plaintext credential is destroyed on success and kept on failure
  W4  no token material reaches stdout, stderr or an exception message
  W5  the account is asserted explicitly, and a document that disagrees is
      refused rather than believed
"""
import ast
import json
import secrets
from pathlib import Path

import pytest

import connect_account
import connection as conn
import connection_tokens as tokens
from connect_account import (
    ConnectAccountError,
    address_in_document,
    check_account_agrees,
    connect_account as wire,
    connect_token_document,
    read_token_document,
)
from test_connection_kms import KEY, FakeKms, reference_crc32c


A = "coach@example.test"
B = "other@example.test"
SECRET = "refresh-token-value-that-must-never-appear"
SOURCE = Path("connect_account.py").read_text(encoding="utf-8")


def _provider(client=None):
    from connection_kms import KmsKeyProvider
    return KmsKeyProvider(KEY, client or FakeKms(),
                          crc32c=reference_crc32c)


def _token_file(tmp_path, **overrides):
    document = {"refresh_token": SECRET, "scope": "gmail.modify",
                "token_type": "Bearer"}
    document.update(overrides)
    path = tmp_path / "token.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _root(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    return root


class ExplodingFactory:
    """Any use of this is a real-call attempt, and fails the test loudly."""

    def __call__(self):
        raise AssertionError("a real KMS client was constructed")


# ---------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------

def test_a_collected_credential_becomes_a_connection(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    provider = _provider()

    summary = wire(root, A, token, provider)

    assert summary["account"] == A
    assert conn.occupied_by(root) == A
    assert summary["token_file_destroyed"] is True


def test_the_stored_token_round_trips(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    provider = _provider()
    wire(root, A, token, provider)

    connection = conn.current(root)
    assert tokens.load_token(connection, provider)["refresh_token"] == SECRET


def test_an_in_memory_credential_connects_without_a_plaintext_file(tmp_path):
    root = _root(tmp_path)
    provider = _provider()
    summary = connect_token_document(
        root, A, {"refresh_token": SECRET}, provider
    )
    assert summary["account"] == A
    assert tokens.load_token(conn.current(root), provider)[
        "refresh_token"
    ] == SECRET
    assert list(tmp_path.glob("*.json")) == []


def test_the_stored_record_holds_no_plaintext(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    wire(root, A, token, _provider())

    connection = conn.current(root)
    raw = tokens.token_path(connection).read_text(encoding="utf-8")
    assert SECRET not in raw and "refresh_token" not in raw


def test_reconnecting_the_same_account_is_lossless(tmp_path):
    """The weekly reconnect must not disturb schedule or history."""
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider(),
         timezone="America/New_York", run_at="18:00")
    first = conn.current(root)

    second_file = tmp_path / "again.json"
    second_file.write_text(json.dumps({"refresh_token": "second-value"}),
                           encoding="utf-8")
    wire(root, A, second_file, _provider())

    refreshed = conn.current(root)
    assert refreshed.run_at == first.run_at == "18:00"
    assert refreshed.timezone_name == "America/New_York"
    assert refreshed.connected_at == first.connected_at
    assert refreshed.last_authorized_at >= first.last_authorized_at


# ---------------------------------------------------------------------
# W2  a refusal writes nothing
# ---------------------------------------------------------------------

def test_a_different_account_is_refused(tmp_path):
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider())

    intruder = tmp_path / "intruder.json"
    intruder.write_text(json.dumps({"refresh_token": "intruder"}),
                        encoding="utf-8")
    with pytest.raises(conn.ConnectionOccupied):
        wire(root, B, intruder, _provider())

    assert conn.occupied_by(root) == A


def test_a_refused_connect_does_not_destroy_the_credential(tmp_path):
    """W2: the operator must be able to retry without another consent round."""
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider())

    intruder = tmp_path / "intruder.json"
    intruder.write_text(json.dumps({"refresh_token": "intruder"}),
                        encoding="utf-8")
    with pytest.raises(conn.ConnectionOccupied):
        wire(root, B, intruder, _provider())

    assert intruder.exists()


def test_a_refused_connect_leaves_the_existing_token_intact(tmp_path):
    root = _root(tmp_path)
    provider = _provider()
    wire(root, A, _token_file(tmp_path), provider)

    intruder = tmp_path / "intruder.json"
    intruder.write_text(json.dumps({"refresh_token": "intruder"}),
                        encoding="utf-8")
    with pytest.raises(conn.ConnectionOccupied):
        wire(root, B, intruder, provider)

    assert tokens.load_token(conn.current(root), provider)[
        "refresh_token"] == SECRET


def test_a_failing_kms_leaves_the_credential_file_in_place(tmp_path):
    """W3: a failed store that also deleted the credential costs a re-consent."""
    class Broken:
        def encrypt(self, request, timeout=None):
            raise RuntimeError("kms unavailable")

        def decrypt(self, request, timeout=None):
            raise RuntimeError("kms unavailable")

    root, token = _root(tmp_path), _token_file(tmp_path)
    from connection_kms import KmsKeyProvider
    with pytest.raises(tokens.TokenStoreError):
        wire(root, A, token, KmsKeyProvider(KEY, Broken(), crc32c=reference_crc32c))

    assert token.exists()
    assert json.loads(token.read_text(encoding="utf-8"))["refresh_token"] == SECRET
    assert conn.occupied_by(root) is None
    assert not (root / "active" / "token.enc.json").exists()


def test_a_token_write_failure_never_publishes_the_connection(tmp_path,
                                                               monkeypatch):
    """The KMS may succeed before the encrypted file write fails."""
    root, token = _root(tmp_path), _token_file(tmp_path)

    def fail_write(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(tokens, "atomic_write_json", fail_write)
    with pytest.raises(ConnectAccountError) as caught:
        wire(root, A, token, _provider())

    assert "encrypted credential" in str(caught.value)
    assert conn.occupied_by(root) is None
    assert token.exists()


def test_a_record_write_failure_removes_the_orphaned_token(tmp_path,
                                                            monkeypatch):
    """Two files cannot commit atomically; the safe rollback stays vacant."""
    root, token = _root(tmp_path), _token_file(tmp_path)

    def fail_write(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(conn, "atomic_write_json", fail_write)
    with pytest.raises(ConnectAccountError) as caught:
        wire(root, A, token, _provider())

    assert "connection record" in str(caught.value)
    assert conn.occupied_by(root) is None
    assert not (root / "active" / "token.enc.json").exists()
    assert token.exists()


def test_a_failed_orphan_cleanup_is_reported_not_assumed(tmp_path,
                                                          monkeypatch):
    root, token = _root(tmp_path), _token_file(tmp_path)

    def fail_record(*_args, **_kwargs):
        raise OSError("disk unavailable")

    def fail_cleanup(*_args, **_kwargs):
        raise OSError("unlink unavailable")

    monkeypatch.setattr(conn, "atomic_write_json", fail_record)
    monkeypatch.setattr(tokens, "forget_token", fail_cleanup)
    with pytest.raises(ConnectAccountError) as caught:
        wire(root, A, token, _provider())

    assert "cleanup" in str(caught.value)
    assert "could not be confirmed" in str(caught.value)
    assert conn.occupied_by(root) is None
    assert token.exists()


def test_the_credential_can_be_kept_deliberately(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    summary = wire(root, A, token, _provider(), destroy_token_file=False)
    assert token.exists()
    assert summary["token_file_destroyed"] is False


# ---------------------------------------------------------------------
# W5  the account assertion
# ---------------------------------------------------------------------

def test_a_document_naming_another_account_is_refused(tmp_path):
    root = _root(tmp_path)
    token = _token_file(tmp_path, email=B)
    with pytest.raises(ConnectAccountError) as caught:
        wire(root, A, token, _provider())
    assert "different account" in str(caught.value)
    assert conn.occupied_by(root) is None


def test_a_document_naming_the_same_account_is_accepted(tmp_path):
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path, email=A.upper()), _provider())
    assert conn.occupied_by(root) == A


@pytest.mark.parametrize("key", ["email", "account", "email_address"])
def test_any_address_field_is_cross_checked(key):
    with pytest.raises(ConnectAccountError):
        check_account_agrees({key: B}, A)


def test_a_document_with_no_address_is_accepted_on_the_operators_word():
    """The current broker seals no address, deliberately."""
    assert address_in_document({"refresh_token": "x"}) is None
    assert check_account_agrees({"refresh_token": "x"}, A) is None


def test_an_empty_address_field_is_not_treated_as_a_claim():
    assert address_in_document({"email": "   "}) is None


# ---------------------------------------------------------------------
# Rejecting unusable credentials
# ---------------------------------------------------------------------

def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(ConnectAccountError) as caught:
        read_token_document(tmp_path / "nope.json")
    assert "no credential file" in str(caught.value)


def test_a_document_without_a_refresh_token_is_refused(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"access_token": "short-lived"}),
                    encoding="utf-8")
    with pytest.raises(ConnectAccountError) as caught:
        read_token_document(path)
    assert "refresh_token" in str(caught.value)


def test_an_empty_refresh_token_is_refused(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"refresh_token": ""}), encoding="utf-8")
    with pytest.raises(ConnectAccountError):
        read_token_document(path)


def test_malformed_json_is_refused(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConnectAccountError) as caught:
        read_token_document(path)
    assert "not valid JSON" in str(caught.value)


def test_a_json_array_is_not_a_credential(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ConnectAccountError):
        read_token_document(path)


# ---------------------------------------------------------------------
# W4  nothing leaks
# ---------------------------------------------------------------------

def test_no_error_message_carries_the_token(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"access_token": SECRET}), encoding="utf-8")
    with pytest.raises(ConnectAccountError) as caught:
        read_token_document(path)
    assert SECRET not in str(caught.value)


def test_the_cli_prints_no_token_material(tmp_path, capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)

    captured = capsys.readouterr()
    assert SECRET not in captured.out and SECRET not in captured.err


def test_a_kms_failure_prints_no_token_material(tmp_path, capsys):
    class Broken:
        def encrypt(self, request, timeout=None):
            raise RuntimeError(f"failed handling {SECRET}")

        def decrypt(self, request, timeout=None):
            raise RuntimeError("no")

    root, token = _root(tmp_path), _token_file(tmp_path)
    code = connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--yes",
    ], client_factory=Broken, crc32c=reference_crc32c)

    captured = capsys.readouterr()
    assert code == 1
    assert SECRET not in captured.out and SECRET not in captured.err


# ---------------------------------------------------------------------
# W1  no real client, ever, in a test
# ---------------------------------------------------------------------

def test_the_google_import_is_deferred_inside_the_factory():
    """W1: at module scope it would make importing this module reach out."""
    tree = ast.parse(SOURCE)
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in getattr(node, "names", [])]
            module = getattr(node, "module", "") or ""
            assert "google" not in module, (
                "google is imported at module scope; importing this module "
                "must reach nothing"
            )
            assert not any(n.startswith("google") for n in names)


def test_the_deferred_import_really_is_inside_the_default_factory():
    """The positive half: the import exists, just not at the top."""
    tree = ast.parse(SOURCE)
    factory = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "default_kms_client"
    )
    imports = [n for n in ast.walk(factory)
               if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert imports, "default_kms_client no longer imports anything"


def test_an_injected_factory_is_used_instead_of_the_default(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    used = []

    def factory():
        used.append(True)
        return FakeKms()

    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--yes",
    ], client_factory=factory, crc32c=reference_crc32c)
    assert used == [True]


def test_the_default_factory_is_never_reached_when_one_is_injected(tmp_path):
    """Proves the seam holds: an exploding default is never called."""
    root, token = _root(tmp_path), _token_file(tmp_path)
    original = connect_account.default_kms_client
    connect_account.default_kms_client = ExplodingFactory()
    try:
        code = connect_account.main([
            "--root", str(root), "--account", A, "--token", str(token),
            "--kms-key", KEY, "--yes",
        ], client_factory=FakeKms, crc32c=reference_crc32c)
    finally:
        connect_account.default_kms_client = original
    assert code == 0


def test_no_module_in_the_import_closure_reaches_google():
    """Nothing this module pulls in imports a Google library at module scope."""
    local = {p.name for p in Path(".").glob("*.py")}
    seen, pending = set(), ["connect_account.py"]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        tree = ast.parse(Path(name).read_text(encoding="utf-8"))
        for node in tree.body:
            modules = []
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                assert not module.startswith(("google", "googleapiclient")), (
                    f"{name} imports {module} at module scope"
                )
                if f"{module.split('.')[0]}.py" in local:
                    pending.append(f"{module.split('.')[0]}.py")


# ---------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------

def test_it_refuses_without_yes(tmp_path):
    root, token = _root(tmp_path), _token_file(tmp_path)
    with pytest.raises(SystemExit) as caught:
        connect_account.main([
            "--root", str(root), "--account", A, "--token", str(token),
            "--kms-key", KEY,
        ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert caught.value.code != 0
    assert conn.occupied_by(root) is None
    assert token.exists()


def test_a_missing_kms_key_is_refused_before_anything_is_written(tmp_path,
                                                                 capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    code = connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", "", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)

    assert code == 1
    assert conn.occupied_by(root) is None
    assert token.exists()
    assert "CONNECTION_KMS_KEY" in capsys.readouterr().err


def test_an_occupied_connection_exits_distinctly(tmp_path, capsys):
    """A refusal is not the same kind of event as a failure."""
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider())

    intruder = tmp_path / "i.json"
    intruder.write_text(json.dumps({"refresh_token": "x"}), encoding="utf-8")
    code = connect_account.main([
        "--root", str(root), "--account", B, "--token", str(intruder),
        "--kms-key", KEY, "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)

    assert code == 2
    assert "Disconnect it first" in capsys.readouterr().err


def test_a_failure_says_the_credential_is_still_there(tmp_path, capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", "", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert "left in place" in capsys.readouterr().err


def test_an_ignored_schedule_flag_is_reported(tmp_path, capsys):
    """Silently ignored input is its own bug."""
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider(), run_at="18:00")

    again = tmp_path / "again.json"
    again.write_text(json.dumps({"refresh_token": "x"}), encoding="utf-8")
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(again),
        "--kms-key", KEY, "--run-at", "07:30", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)

    assert "does not change run_at" in capsys.readouterr().err
    assert conn.current(root).run_at == "18:00"


def test_a_matching_schedule_flag_is_not_reported_as_ignored(tmp_path, capsys):
    root = _root(tmp_path)
    wire(root, A, _token_file(tmp_path), _provider(), run_at="18:00")

    again = tmp_path / "again.json"
    again.write_text(json.dumps({"refresh_token": "x"}), encoding="utf-8")
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(again),
        "--kms-key", KEY, "--run-at", "18:00", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert "does not change" not in capsys.readouterr().err


def test_a_first_connection_reports_no_ignored_flags(tmp_path, capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--run-at", "07:30", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert "does not change" not in capsys.readouterr().err
    assert conn.current(root).run_at == "07:30"


def test_the_summary_confirms_the_credential_was_destroyed(tmp_path, capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert "plaintext credential destroyed" in capsys.readouterr().out


def test_keeping_the_credential_says_so_loudly(tmp_path, capsys):
    root, token = _root(tmp_path), _token_file(tmp_path)
    connect_account.main([
        "--root", str(root), "--account", A, "--token", str(token),
        "--kms-key", KEY, "--keep-token-file", "--yes",
    ], client_factory=FakeKms, crc32c=reference_crc32c)
    assert "STILL AT" in capsys.readouterr().out
