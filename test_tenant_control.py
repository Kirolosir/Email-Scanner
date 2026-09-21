import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from connection_tokens import FileKeyProvider
from hosted_control import HostedControlError
from mailbox_tokens import seal_mailbox_token
from tenant_store import Mailbox
from tenant_control import IDENTITY_SCOPES, MAILBOX_SCOPES, LoginResult, TenantControl


class Credentials:
    id_token = "signed-identity"

    def to_json(self):
        return json.dumps({"refresh_token": "private-refresh"})


class FakeFlow:
    def __init__(self, scopes, state=None, code_verifier=None):
        self.scopes = tuple(scopes)
        self.state = state
        self.code_verifier = code_verifier or "pkce-verifier"
        self.credentials = Credentials()
        self.fetched = []

    def authorization_url(self, **_kwargs):
        purpose = "mailbox" if tuple(self.scopes) == MAILBOX_SCOPES else "login"
        return f"https://accounts.example.test/{purpose}", f"{purpose}-state"

    def fetch_token(self, **kwargs):
        self.fetched.append(kwargs)


class FlowFactory:
    def __init__(self):
        self.flows = []

    def __call__(self, _path, scopes, **kwargs):
        kwargs.pop("redirect_uri", None)
        flow = FakeFlow(scopes, **kwargs)
        self.flows.append(flow)
        return flow


class ProfileRequest:
    def execute(self):
        return {"emailAddress": "mailbox@example.test"}


class Service:
    def users(self):
        return self

    def getProfile(self, **_kwargs):
        return ProfileRequest()


class Store:
    def __init__(self):
        self.connections = []

    def connect_mailbox(self, *args):
        self.connections.append(args)
        return "connected-mailbox"


class DisconnectStore(Store):
    def __init__(self, owner, mailbox_id, record):
        super().__init__()
        self.owner = owner
        self.mailbox_id = mailbox_id
        self.record = record
        self.disconnected = []

    def mailbox_for_user(self, user_id, mailbox_id):
        if user_id != self.owner or mailbox_id != self.mailbox_id:
            raise AssertionError("wrong owner or mailbox")
        return Mailbox(
            mailbox_id, user_id, "google-subject-1",
            "mailbox@example.test", None,
        )

    def load_credentials(self, user_id, mailbox_id):
        assert (user_id, mailbox_id) == (self.owner, self.mailbox_id)
        return self.record

    def disconnect_mailbox(self, user_id, mailbox_id):
        self.disconnected.append((user_id, mailbox_id))
        return True


def _config(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"web": {"client_id": "client-123"}}))
    return SimpleNamespace(
        credentials_path=Path(path),
        redirect_uri="https://example.test/oauth/callback",
        kms_key="projects/p/locations/l/keyRings/r/cryptoKeys/k",
    )


def _claims(_raw_token, audience):
    assert audience == "client-123"
    return {
        "iss": "https://accounts.google.com",
        "sub": "google-subject-1",
        "email": "mailbox@example.test",
        "email_verified": True,
    }


def _control(tmp_path, store=None, verifier=_claims):
    flows = FlowFactory()
    store = store or Store()
    control = TenantControl(
        _config(tmp_path), store, flow_factory=flows,
        service_builder=lambda *_args, **_kwargs: Service(),
        provider_builder=lambda _key: object(), token_verifier=verifier,
    )
    return control, flows, store


def test_website_login_and_mailbox_authorization_use_separate_scopes(tmp_path):
    control, flows, _store = _control(tmp_path)
    user_id = uuid.uuid4()
    assert control.begin_login().endswith("/login")
    assert control.begin_mailbox_connect(user_id).endswith("/mailbox")
    assert flows.flows[0].scopes == IDENTITY_SCOPES
    assert flows.flows[1].scopes == MAILBOX_SCOPES


def test_login_callback_returns_verified_stable_identity(tmp_path):
    control, _flows, _store = _control(tmp_path)
    control.begin_login()
    result = control.complete_login(urlencode({
        "state": "login-state", "code": "one-use-code",
    }))
    assert result == LoginResult(
        "https://accounts.google.com",
        "google-subject-1",
        "mailbox@example.test",
    )


def test_login_state_cannot_authorize_a_mailbox(tmp_path):
    control, _flows, store = _control(tmp_path)
    control.begin_login()
    with pytest.raises(HostedControlError) as caught:
        control.complete_mailbox_connect(urlencode({
            "state": "login-state", "code": "code",
        }), uuid.uuid4())
    assert caught.value.code == "state_expired"
    assert store.connections == []


def test_mailbox_state_is_bound_to_the_user_who_started_it(tmp_path):
    control, _flows, store = _control(tmp_path)
    owner = uuid.uuid4()
    control.begin_mailbox_connect(owner)
    with pytest.raises(HostedControlError) as caught:
        control.complete_mailbox_connect(urlencode({
            "state": "mailbox-state", "code": "code",
        }), uuid.uuid4())
    assert caught.value.code == "state_expired"
    assert store.connections == []


def test_mailbox_callback_verifies_identity_and_stores_for_owner(tmp_path):
    store = Store()
    control, _flows, _store = _control(tmp_path, store=store)
    owner = uuid.uuid4()
    control.begin_mailbox_connect(owner)
    result = control.complete_mailbox_connect(urlencode({
        "state": "mailbox-state", "code": "code",
    }), owner)
    assert result == "connected-mailbox"
    assert store.connections[0][0:3] == (
        owner, "google-subject-1", "mailbox@example.test"
    )
    assert store.connections[0][3] == {"refresh_token": "private-refresh"}


def test_mailbox_identity_must_match_the_gmail_profile(tmp_path):
    def different_mailbox(_raw, _audience):
        claims = _claims(_raw, "client-123")
        claims["email"] = "different@example.test"
        return claims

    control, _flows, store = _control(tmp_path, verifier=different_mailbox)
    owner = uuid.uuid4()
    control.begin_mailbox_connect(owner)
    with pytest.raises(HostedControlError) as caught:
        control.complete_mailbox_connect(urlencode({
            "state": "mailbox-state", "code": "code",
        }), owner)
    assert caught.value.code == "gmail_profile_failed"
    assert store.connections == []


def test_unverified_identity_is_refused(tmp_path):
    def unverified(_raw, _audience):
        claims = _claims(_raw, "client-123")
        claims["email_verified"] = False
        return claims

    control, _flows, _store = _control(tmp_path, verifier=unverified)
    control.begin_login()
    with pytest.raises(HostedControlError) as caught:
        control.complete_login(urlencode({
            "state": "login-state", "code": "code",
        }))
    assert caught.value.code == "token_exchange_failed"


def test_disconnect_revokes_and_removes_only_the_owned_mailbox(tmp_path):
    owner = uuid.uuid4()
    mailbox_id = uuid.uuid4()
    provider = FileKeyProvider(tmp_path / "key").create()
    record = seal_mailbox_token(
        mailbox_id, {"refresh_token": "private-refresh"}, provider
    )
    store = DisconnectStore(owner, mailbox_id, record)
    revoked = []
    control, _flows, _store = _control(tmp_path, store=store)
    control._provider_builder = lambda _key: provider
    control._revoker = lambda document: revoked.append(document) or True
    assert control.disconnect_mailbox(
        owner, mailbox_id, "mailbox@example.test"
    ) is True
    assert revoked == [{"refresh_token": "private-refresh"}]
    assert store.disconnected == [(owner, mailbox_id)]


def test_disconnect_refuses_wrong_confirmation_before_loading_token(tmp_path):
    owner = uuid.uuid4()
    mailbox_id = uuid.uuid4()
    provider = FileKeyProvider(tmp_path / "key").create()
    record = seal_mailbox_token(
        mailbox_id, {"refresh_token": "private-refresh"}, provider
    )
    store = DisconnectStore(owner, mailbox_id, record)
    control, _flows, _store = _control(tmp_path, store=store)
    with pytest.raises(HostedControlError):
        control.disconnect_mailbox(owner, mailbox_id, "wrong@example.test")
    assert store.disconnected == []
