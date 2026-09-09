import ast
import datetime as dt
import io
import json
from urllib.parse import urlencode

import connection
from hosted_dashboard import HostedDashboardApp
from hosted_status import HostedConfig


BEARER = "b" * 48


def _app(tmp_path, control=None, run_requester=None, clock=None):
    config = HostedConfig(
        tmp_path, BEARER, require_forwarded_https=False,
        require_mountpoint=False, verify_root=False,
    )
    return HostedDashboardApp(
        config, control=control, run_requester=run_requester, clock=clock
    )


def _call(app, path="/", method="GET", form="", cookie="", query=""):
    body = form.encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "HTTP_COOKIE": cookie,
        "QUERY_STRING": query,
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response)).decode("utf-8")
    captured["body"] = payload
    return captured


def _login(app):
    response = _call(
        app, "/login", "POST", "access_key=" + BEARER
    )
    return response["headers"]["Set-Cookie"].split(";", 1)[0]


def _settings_form(app, **changes):
    form = {
        "csrf": app._csrf_value(),
        "labels": "Scheduling | AI/Scheduling\nFinance | AI/Finance",
        "timezone": "America/New_York",
        "run_at": "18:00",
        "display_name": "Owner",
        "signature": "Owner",
        "max_scan": "50",
        "limit": "40",
        "max_drafts": "8",
        "confirm_unsent_drafts": "yes",
    }
    form.update(changes)
    return urlencode(form)


def test_dashboard_requires_login(tmp_path):
    response = _call(_app(tmp_path))
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == "/login"


def test_wrong_access_key_is_refused(tmp_path):
    response = _call(
        _app(tmp_path), "/login", "POST", "access_key=wrong"
    )
    assert response["status"].startswith("401")
    assert "Set-Cookie" not in response["headers"]


def test_google_is_the_primary_login_and_key_is_only_a_fallback(tmp_path):
    page = _call(_app(tmp_path, control=object()), "/login")
    assert page["status"].startswith("200")
    assert "Continue with Google" in page["body"]
    assert 'action="/connect"' in page["body"]
    assert "Use private access key instead" in page["body"]


def test_login_cookie_opens_the_dashboard(tmp_path):
    app = _app(tmp_path)
    response = _call(app, cookie=_login(app))
    assert response["status"].startswith("200")
    assert "No Gmail account connected" in response["body"]


def test_connected_dashboard_shows_safe_counts_and_labels(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "success", "finished_at": "2026-09-08T18:05:00Z",
            "counts": {"scanned": 9, "drafted": 3},
            "subject": "PRIVATE SUBJECT",
        },
    }), encoding="utf-8")
    (seat.directory / "account.json").write_text(json.dumps({
        "taxonomy": [{
            "display": "Scheduling", "label": "AI/Scheduling",
            "description": "PRIVATE DESCRIPTION",
            "examples": ["PRIVATE SUBJECT"],
            "drafting": {"mode": "generic"},
        }],
    }), encoding="utf-8")
    app = _app(tmp_path)
    response = _call(app, cookie=_login(app))

    assert "owner@example.test" in response["body"]
    assert "AI/Scheduling" in response["body"]
    assert "scanned" in response["body"] and ">9<" in response["body"]
    assert "drafted" in response["body"] and ">3<" in response["body"]
    assert "PRIVATE SUBJECT" not in response["body"]
    assert "PRIVATE DESCRIPTION" not in response["body"]


def test_dashboard_never_reads_or_imports_token_modules():
    tree = ast.parse(open("hosted_dashboard.py", encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    for forbidden in (
        "connection_tokens", "connection_kms", "gmail_auth",
        "googleapiclient", "gemini_client", "drafting",
    ):
        assert forbidden not in imported


def test_security_headers_are_on_login_and_dashboard(tmp_path):
    app = _app(tmp_path)
    for response in (
        _call(app, "/login"), _call(app, cookie=_login(app))
    ):
        headers = response["headers"]
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in headers["Content-Security-Policy"]


def test_logout_requires_csrf(tmp_path):
    app = _app(tmp_path)
    cookie = _login(app)
    assert _call(app, "/logout", "POST", "csrf=wrong", cookie)[
        "status"
    ].startswith("403")


def test_connected_owner_can_open_and_save_settings(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    app = _app(tmp_path)
    cookie = _login(app)

    page = _call(app, "/settings", cookie=cookie)
    assert page["status"].startswith("200")
    assert "Shape your daily assistant" in page["body"]
    assert "Nothing is auto-sent" not in page["body"]
    assert "Responses must stay unsent" in page["body"]

    response = _call(
        app, "/settings", "POST", _settings_form(app), cookie
    )
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == "/?saved=1"
    for name in (
        "account.json", "taxonomy-confirmation.json",
        "ai-drafting-approval.json", "label-setup-pending.json",
    ):
        assert (seat.directory / name).is_file()


def test_settings_save_requires_csrf_and_draft_confirmation(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    app = _app(tmp_path)
    cookie = _login(app)

    refused = _call(
        app, "/settings", "POST",
        _settings_form(app, csrf="wrong"), cookie,
    )
    assert refused["status"].startswith("403")
    assert not (seat.directory / "account.json").exists()

    unconfirmed = _call(
        app, "/settings", "POST",
        _settings_form(app, confirm_unsent_drafts=""), cookie,
    )
    assert unconfirmed["status"].startswith("400")
    assert "unsent drafts" in unconfirmed["body"]
    assert not (seat.directory / "account.json").exists()


def test_settings_errors_escape_redisplayed_values(tmp_path):
    connection.connect(tmp_path, "owner@example.test")
    app = _app(tmp_path)
    cookie = _login(app)
    response = _call(
        app, "/settings", "POST",
        _settings_form(app, signature="<script>alert(1)</script>", max_scan="bad"),
        cookie,
    )
    assert response["status"].startswith("400")
    assert "<script>" not in response["body"]
    assert "&lt;script&gt;" in response["body"]


def test_connect_is_csrf_protected_and_redirects_to_google(tmp_path):
    class Control:
        def __init__(self):
            self.calls = 0

        def begin_connect(self):
            self.calls += 1
            return "https://accounts.example.test/authorize"

    control = Control()
    app = _app(tmp_path, control=control)
    cookie = _login(app)
    refused = _call(app, "/connect", "POST", "csrf=wrong", cookie)
    assert refused["status"].startswith("403") and control.calls == 0

    response = _call(
        app, "/connect", "POST",
        urlencode({"csrf": app._csrf_value()}), cookie,
    )
    assert response["status"].startswith("303")
    assert response["headers"]["Location"].startswith("https://accounts.")
    assert control.calls == 1

    anonymous = _call(
        app, "/connect", "POST",
        urlencode({"csrf": app._csrf_value()}),
    )
    assert anonymous["status"].startswith("303")
    assert anonymous["headers"]["Location"].startswith("https://accounts.")
    assert control.calls == 2


def test_dashboard_has_google_link_and_immediate_run_controls(tmp_path):
    app = _app(tmp_path, control=object())
    vacant = _call(app, cookie=_login(app))
    assert "Link Google account" in vacant["body"]
    assert "Run now" in vacant["body"]
    assert 'title="Link Google first"' in vacant["body"]

    connection.connect(tmp_path, "owner@example.test")
    connected = _call(app, cookie=_login(app))
    assert 'action="/connect"' in connected["body"]
    assert 'action="/run-now"' in connected["body"]


def test_run_now_is_csrf_protected_and_queues_one_request(tmp_path):
    connection.connect(tmp_path, "owner@example.test")
    calls = []

    def request_run(root, *, now):
        calls.append((root, now))
        return 1788969600

    app = _app(tmp_path, run_requester=request_run)
    cookie = _login(app)
    refused = _call(app, "/run-now", "POST", "csrf=wrong", cookie)
    assert refused["status"].startswith("403")
    assert calls == []

    response = _call(
        app, "/run-now", "POST",
        urlencode({"csrf": app._csrf_value()}), cookie,
    )
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == (
        "/?run=requested&after=1788969600"
    )
    assert len(calls) == 1 and calls[0][0] == tmp_path


def test_run_page_auto_refreshes_while_working_then_reports_completion(tmp_path):
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    seat = connection.connect(tmp_path, "owner@example.test", now=now)
    app = _app(tmp_path, clock=lambda: now)
    cookie = _login(app)
    epoch = int(now.timestamp())
    status_path = seat.directory / "daily-status.json"
    status_path.write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "running", "started_at": now.isoformat(),
            "finished_at": None, "safe_error_codes": [], "counts": {},
        },
    }), encoding="utf-8")

    working = _call(
        app, cookie=cookie, query=f"run=checking&after={epoch}"
    )
    assert working["headers"]["Refresh"].startswith("4;")
    assert "Run in progress" in working["body"]

    document = json.loads(status_path.read_text(encoding="utf-8"))
    document["last_run"]["outcome"] = "success"
    document["last_run"]["finished_at"] = now.isoformat()
    status_path.write_text(json.dumps(document), encoding="utf-8")
    complete = _call(
        app, cookie=cookie, query=f"run=checking&after={epoch}"
    )
    assert "Refresh" not in complete["headers"]
    assert "Run complete" in complete["body"]


def test_run_page_ignores_impossible_request_timestamp(tmp_path):
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    connection.connect(tmp_path, "owner@example.test", now=now)
    app = _app(tmp_path, clock=lambda: now)
    response = _call(
        app, cookie=_login(app), query="run=checking&after=999999999999999999"
    )
    assert response["status"].startswith("200")
    assert "Refresh" not in response["headers"]


def test_dashboard_explains_when_google_must_be_reconnected(tmp_path):
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    seat = connection.connect(
        tmp_path, "owner@example.test", now=now - dt.timedelta(hours=1)
    )
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "failed",
            "started_at": now.isoformat(),
            "finished_at": now.isoformat(),
            "safe_error_codes": ["gmail_reauthorization_required"],
            "counts": {"failures": 1},
        },
    }), encoding="utf-8")
    app = _app(tmp_path, control=object(), clock=lambda: now)
    response = _call(app, cookie=_login(app))
    assert "Google needs to be reconnected" in response["body"]
    assert "Link Google account" in response["body"]


def test_successful_reconnection_clears_an_old_google_error(tmp_path):
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    seat = connection.connect(
        tmp_path, "owner@example.test", now=now - dt.timedelta(hours=2)
    )
    failed_at = now - dt.timedelta(hours=1)
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "failed",
            "started_at": failed_at.isoformat(),
            "finished_at": failed_at.isoformat(),
            "safe_error_codes": ["gmail_reauthorization_required"],
            "counts": {"failures": 1},
        },
    }), encoding="utf-8")
    connection.connect(tmp_path, "owner@example.test", now=now)
    app = _app(tmp_path, control=object(), clock=lambda: now)
    response = _call(app, cookie=_login(app))
    assert "Google needs to be reconnected" not in response["body"]


def test_oauth_callback_uses_state_without_dashboard_cookie(tmp_path):
    queries = []

    class Control:
        def complete_connect(self, query):
            queries.append(query)

    app = _app(tmp_path, control=Control())
    body = b""
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/oauth/callback",
        "QUERY_STRING": "state=safe-state&code=one-time-code",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(body),
        "HTTP_COOKIE": "",
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    assert b"".join(app(environ, start_response)) == b""
    assert captured["status"].startswith("303")
    assert captured["headers"]["Location"] == "/?connected=1"
    assert "HttpOnly" in captured["headers"]["Set-Cookie"]
    assert "SameSite=Strict" in captured["headers"]["Set-Cookie"]
    assert queries == ["state=safe-state&code=one-time-code"]


def test_disconnect_requires_csrf_and_passes_typed_address(tmp_path):
    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def __init__(self):
            self.confirmations = []

        def disconnect(self, confirmation):
            self.confirmations.append(confirmation)

    control = Control()
    app = _app(tmp_path, control=control)
    cookie = _login(app)
    assert _call(
        app, "/disconnect", "POST", "csrf=wrong", cookie
    )["status"].startswith("403")
    response = _call(
        app, "/disconnect", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": address}),
        cookie,
    )
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == "/?disconnected=1"
    assert control.confirmations == [address]


def test_service_binds_to_loopback_and_runs_unprivileged():
    unit = open("hosted-dashboard.service.example", encoding="utf-8").read()
    assert "User=email-scanner" in unit
    assert "--bind 127.0.0.1:8081" in unit
    assert "--bind 0.0.0.0" not in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/mnt/state" in unit
    assert "--access-logfile /dev/null" in unit
