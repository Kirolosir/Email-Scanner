import datetime as dt
import io
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from tenant_dashboard import TenantDashboardApp
from tenant_store import (
    IssuedSession,
    SessionIdentity,
    TenantAccessDenied,
    MailboxView,
    csrf_value,
)


NOW = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)


class Store:
    def __init__(self):
        self.user_id = uuid.uuid4()
        self.identity = SessionIdentity(
            uuid.uuid4(), self.user_id, "owner@example.test", b"c" * 32,
            NOW + dt.timedelta(days=1),
        )
        self.revoked = []
        self.enqueued = []
        self.session_issued = False

    def authenticate_session(self, token, **_kwargs):
        if token != "valid-session":
            raise TenantAccessDenied("invalid session")
        return self.identity

    def create_or_get_user(self, *_args):
        return self.user_id

    def issue_session(self, user_id, **_kwargs):
        assert user_id == self.user_id
        self.session_issued = True
        return IssuedSession("new-session", self.identity)

    def revoke_session(self, *args, **_kwargs):
        self.revoked.append(args)
        return True

    def mailboxes_for_user(self, user_id):
        assert user_id == self.user_id
        return []

    def mailbox_view_for_user(self, user_id, mailbox_id):
        assert user_id == self.user_id
        return MailboxView(
            mailbox_id, "owner@example.test", "UTC", dt.time(18, 0),
            True, None, None, 0, None, "pending",
        )

    def enqueue_job(self, *args):
        self.enqueued.append(args)
        return uuid.uuid4()

    def enqueue_job_if_idle(self, *args, **kwargs):
        self.enqueued.append(args + (kwargs,))
        return uuid.uuid4()

    def set_mailbox_enabled(self, *args, **kwargs):
        self.schedule = args + (kwargs,)
        return True


class Control:
    def __init__(self):
        self.connected_for = []
        self.disconnected = []

    def begin_login(self):
        return "https://accounts.example.test/login"

    def complete_login(self, _query):
        return SimpleNamespace(
            issuer="https://accounts.google.com", subject="subject-1",
            email="owner@example.test",
        )

    def begin_mailbox_connect(self, user_id):
        self.connected_for.append(user_id)
        return "https://accounts.example.test/mailbox"

    def complete_mailbox_connect(self, _query, _user_id):
        return True

    def disconnect_mailbox(self, *args):
        self.disconnected.append(args)
        return True


def _app(state_root=None):
    store = Store()
    control = Control()
    config = SimpleNamespace(
        require_forwarded_https=False,
        state_root=Path(state_root or "/unused-state-root"),
    )
    return TenantDashboardApp(
        config, store, control, clock=lambda: NOW
    ), store, control


def _call(app, path="/", method="GET", form="", cookie="", query=""):
    body = form.encode()
    environ = {
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "HTTP_COOKIE": cookie,
        "QUERY_STRING": query,
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    captured["body"] = b"".join(app(environ, start_response)).decode()
    return captured


def _cookie():
    return "email_scanner_session=valid-session"


def _form(store, **extra):
    values = {"csrf": csrf_value(store.identity)}
    values.update(extra)
    return urlencode(values)


def test_signed_out_user_is_redirected_to_website_login():
    app, _store, _control = _app()
    response = _call(app)
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == "/login"


def test_login_callback_creates_a_user_specific_session():
    app, store, _control = _app()
    response = _call(app, "/oauth/callback", query="state=s&code=c")
    assert response["status"].startswith("303")
    assert "email_scanner_session=new-session" in response["headers"]["Set-Cookie"]
    assert store.session_issued is True


def test_sign_out_revokes_only_the_website_session():
    app, store, control = _app()
    response = _call(
        app, "/logout", "POST", _form(store), cookie=_cookie()
    )
    assert response["status"].startswith("303")
    assert "Max-Age=0" in response["headers"]["Set-Cookie"]
    assert store.revoked == [(store.identity.session_id, store.user_id)]
    assert control.disconnected == []


def test_disconnect_is_separate_and_keeps_the_session():
    app, store, control = _app()
    mailbox_id = uuid.uuid4()
    response = _call(
        app, "/disconnect", "POST",
        _form(store, mailbox_id=mailbox_id, confirmation="owner@example.test"),
        cookie=_cookie(),
    )
    assert response["headers"]["Location"] == "/?notice=disconnected"
    assert control.disconnected == [
        (store.user_id, mailbox_id, "owner@example.test")
    ]
    assert store.revoked == []
    assert "Set-Cookie" not in response["headers"]


def test_run_request_carries_the_signed_in_user_and_mailbox():
    app, store, _control = _app()
    mailbox_id = uuid.uuid4()
    response = _call(
        app, "/run-now", "POST",
        _form(store, mailbox_id=mailbox_id), cookie=_cookie(),
    )
    assert response["headers"]["Location"] == "/?notice=run-queued"
    assert store.enqueued[0][0:3] == (
        store.user_id, mailbox_id, "incoming"
    )


def test_history_scan_validates_count_and_queues_backfill():
    app, store, _control = _app()
    mailbox_id = uuid.uuid4()
    invalid = _call(
        app, "/backfill", "POST",
        _form(store, mailbox_id=mailbox_id, count="9"), cookie=_cookie(),
    )
    assert invalid["headers"]["Location"] == "/?notice=invalid-count"

    response = _call(
        app, "/backfill", "POST",
        _form(store, mailbox_id=mailbox_id, count="1000"), cookie=_cookie(),
    )
    assert response["headers"]["Location"] == "/?notice=backfill-queued"
    assert store.enqueued[-1][0:3] == (
        store.user_id, mailbox_id, "backfill"
    )
    assert store.enqueued[-1][-1]["requested_count"] == 1000


def test_schedule_can_be_paused_without_disconnect():
    app, store, _control = _app()
    mailbox_id = uuid.uuid4()
    response = _call(
        app, "/schedule", "POST",
        _form(store, mailbox_id=mailbox_id, enabled="0"), cookie=_cookie(),
    )
    assert response["headers"]["Location"] == "/?notice=schedule-off"
    assert store.schedule[0:3] == (store.user_id, mailbox_id, False)


def test_dashboard_shows_history_schedule_progress_and_results(tmp_path):
    app, store, _control = _app(tmp_path)
    mailbox_id = uuid.uuid4()
    store.mailboxes_for_user = lambda _user_id: [MailboxView(
        mailbox_id, "coach@example.test", "America/New_York",
        dt.time(18, 0), True, NOW + dt.timedelta(hours=2), "running",
        200, 1000, "ready", uuid.uuid4(), "backfill", NOW,
        NOW - dt.timedelta(minutes=4), None, None, 200, 1, None,
    )]

    response = _call(app, cookie=_cookie())

    assert response["status"].startswith("200")
    assert "Scan previous emails" in response["body"]
    assert 'max="5000"' in response["body"]
    assert "Daily automation" in response["body"]
    assert "Groups 1/5" in response["body"]
    assert "Remaining: 800" in response["body"]
    assert "Retried" in response["body"]


def test_mutating_routes_require_the_session_specific_csrf_token():
    app, store, control = _app()
    response = _call(
        app, "/connect", "POST", "csrf=wrong", cookie=_cookie()
    )
    assert response["status"].startswith("403")
    assert control.connected_for == []
    assert store.revoked == []


def test_settings_page_is_scoped_to_the_requested_owned_mailbox(tmp_path):
    app, store, _control = _app(tmp_path)
    mailbox_id = uuid.uuid4()
    response = _call(
        app, "/settings", cookie=_cookie(),
        query=urlencode({"mailbox_id": mailbox_id}),
    )
    assert response["status"].startswith("200")
    assert "owner@example.test" in response["body"]
    assert str(mailbox_id) in response["body"]
