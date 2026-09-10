import json

import pytest

import connection
from connection_tokens import FileKeyProvider
import hosted_control as control_module


A = "owner@example.test"


class _Credentials:
    def to_json(self):
        return json.dumps({"refresh_token": "refresh-value"})


class _Flow:
    def __init__(self, calls, kwargs):
        self.calls = calls
        self.kwargs = kwargs
        self.code_verifier = kwargs.get("code_verifier") or "v" * 64
        self.credentials = _Credentials()

    def authorization_url(self, **kwargs):
        self.calls.append(("authorization", kwargs))
        return "https://accounts.example.test/authorize", "state-value"

    def fetch_token(self, **kwargs):
        self.calls.append(("exchange", kwargs, self.kwargs))


class _Service:
    def users(self):
        return self

    def getProfile(self, **_kwargs):
        return object()


def _control(tmp_path, monkeypatch, *, address=A, revoker=None, clock=None):
    root = tmp_path / "state"
    root.mkdir()
    credentials = tmp_path / "credentials.json"
    credentials.write_text("{}", encoding="utf-8")
    key = FileKeyProvider(tmp_path / "kek").create()
    calls = []

    def flow_factory(_path, _scopes, **kwargs):
        return _Flow(calls, kwargs)

    monkeypatch.setattr(
        control_module, "gmail_execute",
        lambda _request: {"emailAddress": address},
    )
    config = control_module.HostedControlConfig(
        root, credentials, "kms-key",
        "http://127.0.0.1:8081/oauth/callback",
    )
    control = control_module.HostedControl(
        config,
        flow_factory=flow_factory,
        service_builder=lambda *_a, **_k: _Service(),
        provider_builder=lambda _name: key,
        revoker=revoker or (lambda _document: True),
        clock=clock or (lambda: 100.0),
    )
    return control, root, calls


def _authorize(control):
    url = control.begin_connect()
    summary = control.complete_connect("state=state-value&code=one-time-code")
    return url, summary


def test_oauth_callback_verifies_gmail_then_stores_only_encrypted_token(
        tmp_path, monkeypatch):
    control, root, calls = _control(tmp_path, monkeypatch)
    url, summary = _authorize(control)

    assert url == "https://accounts.example.test/authorize"
    assert summary["account"] == A
    assert connection.current(root).account == A
    assert (root / "active" / "token.enc.json").is_file()
    assert not any(path.name == "token.json" for path in root.rglob("*"))
    exchange = [call for call in calls if call[0] == "exchange"]
    assert exchange[0][1] == {
        "code": "one-time-code", "include_client_id": True,
    }
    assert exchange[0][2]["state"] == "state-value"
    assert exchange[0][2]["code_verifier"] == "v" * 64


def test_oauth_state_is_single_use_and_expires(tmp_path, monkeypatch):
    now = [100.0]
    control, _root, _calls = _control(
        tmp_path, monkeypatch, clock=lambda: now[0]
    )
    control.begin_connect()
    control.complete_connect("state=state-value&code=first")
    with pytest.raises(
        control_module.HostedControlError, match="already used"
    ) as reused:
        control.complete_connect("state=state-value&code=replay")
    assert reused.value.code == "state_expired"

    control.begin_connect()
    now[0] += control_module.OAUTH_TTL_SECONDS + 1
    with pytest.raises(control_module.HostedControlError, match="expired"):
        control.complete_connect("state=state-value&code=late")


def test_pending_oauth_states_are_bounded_for_a_public_login_page(
        tmp_path, monkeypatch):
    control, _root, _calls = _control(tmp_path, monkeypatch)
    control._states = {
        f"state-{index}": {"verifier": "v", "expires": 200.0}
        for index in range(control_module.MAX_PENDING_OAUTH_STATES)
    }
    with pytest.raises(control_module.HostedControlError, match="too many"):
        control.begin_connect()


def test_different_account_cannot_replace_an_occupied_connection(
        tmp_path, monkeypatch):
    control, root, _calls = _control(
        tmp_path, monkeypatch, address="different@example.test"
    )
    connection.connect(root, A)
    before = (root / "connection.json").read_bytes()
    control.begin_connect()

    with pytest.raises(
        control_module.HostedControlError, match="different"
    ) as mismatch:
        control.complete_connect("state=state-value&code=one-time-code")
    assert mismatch.value.code == "account_mismatch"

    assert (root / "connection.json").read_bytes() == before


def test_disconnect_requires_exact_address_and_revokes_before_local_removal(
        tmp_path, monkeypatch):
    revoked = []
    control, root, _calls = _control(
        tmp_path, monkeypatch,
        revoker=lambda document: revoked.append(document) or True,
    )
    _authorize(control)

    with pytest.raises(control_module.HostedControlError, match="exactly"):
        control.disconnect("wrong@example.test")
    assert connection.current(root).account == A

    manifest = control.disconnect(A)
    assert manifest["revocation"] == "revoked"
    assert revoked == [{"refresh_token": "refresh-value"}]
    assert connection.current(root) is None
    assert not any(
        path.name == "token.enc.json" for path in root.rglob("*")
    )


def test_redirect_uri_accepts_only_https_or_loopback_callback(tmp_path):
    credentials = tmp_path / "credentials.json"
    credentials.write_text("{}", encoding="utf-8")
    for unsafe in (
        "http://example.test/oauth/callback",
        "http://127.0.0.1:8081/wrong",
        "javascript:alert(1)",
    ):
        with pytest.raises(control_module.HostedControlError):
            control_module.HostedControlConfig(
                tmp_path, credentials, "kms-key", unsafe
            )
