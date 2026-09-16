import ast
import datetime as dt
import io
import json
from pathlib import Path
from urllib.parse import urlencode

import connection
import connection_archive
import hosted_run_request
from hosted_dashboard import HostedDashboardApp
from hosted_status import HostedConfig


BEARER = "b" * 48


def _app(tmp_path, control=None, run_requester=None, clock=None,
         undo_requester=None):
    config = HostedConfig(
        tmp_path, BEARER, require_forwarded_https=False,
        require_mountpoint=False, verify_root=False,
    )
    return HostedDashboardApp(
        config, control=control, run_requester=run_requester, clock=clock,
        undo_requester=undo_requester,
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
        "labels": "Scheduling | Scheduling\nFinance | Finance",
        "timezone": "America/New_York",
        "run_at": "18:00",
        "display_name": "Owner",
        "role": "Head Coach",
        "organization": "Example College",
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


def test_google_is_a_direct_login_without_an_access_key_prompt(tmp_path):
    class Control:
        def begin_connect(self):
            return "https://accounts.example.test/authorize?a=1&b=2"

    page = _call(_app(tmp_path, control=Control()), "/login")
    assert page["status"].startswith("200")
    assert "Continue with Google" in page["body"]
    assert 'href="https://accounts.example.test/authorize?a=1&amp;b=2"' in page["body"]
    assert "private access key" not in page["body"].casefold()


def test_oauth_session_cookie_survives_the_cross_site_return(tmp_path):
    cookie = _app(tmp_path)._session_cookie()
    assert "SameSite=Lax" in cookie
    assert "SameSite=Strict" not in cookie


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
            "display": "Scheduling", "label": "Scheduling",
            "description": "PRIVATE DESCRIPTION",
            "examples": ["PRIVATE SUBJECT"],
            "drafting": {"mode": "generic"},
        }],
    }), encoding="utf-8")
    app = _app(tmp_path)
    response = _call(app, cookie=_login(app))

    assert "owner@example.test" in response["body"]
    assert "Scheduling" in response["body"]
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


def test_signout_confirmation_disconnects_gmail_and_clears_session(tmp_path):
    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def __init__(self):
            self.confirmations = []

        def begin_connect(self):
            return "https://accounts.example.test/authorize"

        def disconnect(self, confirmation):
            self.confirmations.append(confirmation)
            connection_archive.disconnect(connection.current(tmp_path), tmp_path)

    control = Control()
    app = _app(tmp_path, control=control)
    cookie = _login(app)

    confirmation = _call(app, "/signout", cookie=cookie)
    assert confirmation["status"].startswith("200")
    assert "Sign out &amp; disconnect" in confirmation["body"]
    assert address in confirmation["body"]

    response = _call(
        app, "/logout", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": address}),
        cookie,
    )
    assert response["status"].startswith("303")
    assert response["headers"]["Location"] == "/login?signed_out=1"
    assert "Max-Age=0" in response["headers"]["Set-Cookie"]
    assert control.confirmations == [address]
    assert connection.current(tmp_path) is None

    page = _call(app, "/login", query="signed_out=1")
    assert "account slot is ready for a different Gmail account" in page["body"]


def test_signout_refuses_wrong_address_without_clearing_session(tmp_path):
    """A real HostedControlError, not a stand-in.

    Previously this test raised a bare ValueError, which happened to produce
    this exact message only because the old code showed the same wording for
    every exception - it was not actually testing a wrong-address mismatch.
    HostedControlError is what disconnect() genuinely raises for one.
    """
    from hosted_control import HostedControlError

    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def disconnect(self, confirmation):
            raise HostedControlError(
                "type the connected Gmail address exactly to disconnect"
            )

    app = _app(tmp_path, control=Control())
    response = _call(
        app, "/logout", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": "wrong@example.test"}),
        _login(app),
    )
    assert response["status"].startswith("400")
    assert "type the connected Gmail address exactly" in response["body"]
    assert "Set-Cookie" not in response["headers"]
    assert connection.current(tmp_path).account == address


def test_signout_does_not_blame_the_typed_address_for_an_unrelated_failure(
        tmp_path):
    """The regression: a lock, an archive write, a revocation call - none of
    these are a confirmation mismatch, and the address was typed correctly.
    Telling the owner to retype it hides the real fault. This was reported
    live: a real disconnect failed with this exact misleading message even
    though the address was typed correctly.
    """
    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def disconnect(self, confirmation):
            raise ValueError("private disconnect detail")

    app = _app(tmp_path, control=Control())
    response = _call(
        app, "/logout", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": address}),
        _login(app),
    )
    assert response["status"].startswith("400")
    assert "type the connected Gmail address exactly" not in response["body"].lower()
    assert "unexpectedly" in response["body"]
    assert "private disconnect detail" not in response["body"]
    assert "Set-Cookie" not in response["headers"]
    assert connection.current(tmp_path).account == address


def test_the_unrelated_signout_failure_is_logged_for_diagnosis(tmp_path, caplog):
    """disconnect() itself never logs; before this fix, this was the only
    place such a failure could be seen at all - and it was hidden."""
    import logging

    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def disconnect(self, confirmation):
            raise ValueError("private disconnect detail")

    app = _app(tmp_path, control=Control())
    with caplog.at_level(logging.ERROR, logger="hosted_dashboard"):
        _call(
            app, "/logout", "POST",
            urlencode({"csrf": app._csrf_value(), "confirmation": address}),
            _login(app),
        )
    assert any("disconnect" in record.message.lower()
              for record in caplog.records)
    assert any("private disconnect detail" in str(record.exc_info)
              for record in caplog.records if record.exc_info)


def test_connected_owner_can_open_and_save_settings(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    app = _app(tmp_path)
    cookie = _login(app)

    page = _call(app, "/settings", cookie=cookie)
    assert page["status"].startswith("200")
    assert "Shape your daily assistant" in page["body"]
    assert "Your voice and program" in page["body"]
    assert 'name="role"' in page["body"]
    assert 'name="organization"' in page["body"]
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
    profile = json.loads((seat.directory / "account.json").read_text())
    assert profile["ai_drafting"]["role"] == "Head Coach"
    assert profile["ai_drafting"]["organization"] == "Example College"


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

    direct = _call(
        app, "/connect", query=urlencode({"csrf": app._csrf_value()})
    )
    assert direct["status"].startswith("303")
    assert direct["headers"]["Location"].startswith("https://accounts.")
    assert control.calls == 3

    refused_direct = _call(app, "/connect", query="csrf=wrong")
    assert refused_direct["status"].startswith("403")
    assert control.calls == 3


def test_dashboard_has_google_link_and_immediate_run_controls(tmp_path):
    app = _app(tmp_path, control=object())
    vacant = _call(app, cookie=_login(app))
    assert "Link Google account" in vacant["body"]
    assert "Scan new mail" in vacant["body"]
    assert 'title="Link Google first"' in vacant["body"]

    connection.connect(tmp_path, "owner@example.test")
    connected = _call(app, cookie=_login(app))
    assert 'method="post" action="/connect"' in connected["body"]
    assert 'action="/run-now"' in connected["body"]
    assert 'action="/run-history"' in connected["body"]
    assert "Scan previous emails" in connected["body"]


def test_hardened_dashboard_disables_the_optional_gunicorn_control_socket():
    unit = Path("hosted-dashboard.service.example").read_text(encoding="utf-8")
    assert "--no-control-socket" in unit


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


def test_history_scan_validates_count_and_queues_the_selected_batch(tmp_path):
    connection.connect(tmp_path, "owner@example.test")
    calls = []

    def request_run(root, *, now, history_count=None):
        calls.append((root, now, history_count))
        return 1788969600

    app = _app(tmp_path, run_requester=request_run)
    cookie = _login(app)
    invalid = _call(
        app, "/run-history", "POST",
        urlencode({"csrf": app._csrf_value(), "message_count": "many"}),
        cookie,
    )
    assert invalid["headers"]["Location"] == "/?run=invalid-count"
    assert calls == []

    response = _call(
        app, "/run-history", "POST",
        urlencode({"csrf": app._csrf_value(), "message_count": "75"}),
        cookie,
    )
    assert response["headers"]["Location"] == (
        "/?run=requested&after=1788969600"
    )
    assert calls[0][2] == 75


def test_valid_history_count_reports_incomplete_account_setup(tmp_path):
    connection.connect(tmp_path, "owner@example.test")
    app = _app(tmp_path)
    cookie = _login(app)

    response = _call(
        app, "/run-history", "POST",
        urlencode({"csrf": app._csrf_value(), "message_count": "10"}),
        cookie,
    )

    assert response["headers"]["Location"] == "/?run=not-ready"


def test_repeat_run_click_reports_existing_work_without_queueing(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "running", "started_at": now.isoformat(),
            "finished_at": None, "safe_error_codes": [], "counts": {},
        },
    }), encoding="utf-8")

    def already_running(*_args, **_kwargs):
        raise hosted_run_request.RunAlreadyActive("running")

    app = _app(tmp_path, run_requester=already_running, clock=lambda: now)
    response = _call(
        app, "/run-history", "POST",
        urlencode({"csrf": app._csrf_value(), "message_count": "50"}),
        _login(app),
    )
    assert response["headers"]["Location"] == (
        f"/?run=already-running&after={int(now.timestamp())}"
    )
    notice = _call(
        app, cookie=_login(app),
        query=f"run=already-running&after={int(now.timestamp())}",
    )
    assert "already running" in notice["body"]
    assert "No duplicate scan was queued" in notice["body"]


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


def test_dashboard_shows_live_progress_without_a_request_query(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "running", "started_at": "2026-09-09T16:00:00+00:00",
            "finished_at": None, "safe_error_codes": [],
            "counts": {"scanned": 50, "drafted": 7},
            "stage": "Creating Gmail labels and drafts",
            "current": 8, "total": 50,
        },
    }), encoding="utf-8")
    app = _app(tmp_path)
    response = _call(app, cookie=_login(app))

    assert response["headers"]["Refresh"].startswith("4;")
    assert "Creating Gmail labels and drafts" in response["body"]
    assert "8 of 50" in response["body"]
    assert 'value="8"' in response["body"]


def test_dashboard_keeps_failed_run_alert_visible(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    (seat.directory / "daily-status.json").write_text(json.dumps({
        "version": 1,
        "last_run": {
            "outcome": "failed", "finished_at": "2026-09-09T16:00:00+00:00",
            "safe_error_codes": ["message_fetch_failed"],
            "counts": {"failures": 1},
        },
    }), encoding="utf-8")
    response = _call(_app(tmp_path), cookie=_login(_app(tmp_path)))

    assert 'role="alert"' in response["body"]
    assert "The last scan stopped safely" in response["body"]
    assert "Some Gmail messages could not be read" in response["body"]


def test_dashboard_renders_recruit_review_queue_without_message_content(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    raw_id = "message-123"
    opaque = __import__("hashlib").sha256(raw_id.encode()).hexdigest()[:16]
    (seat.directory / "daily-state.json").write_text(json.dumps({
        "messages": {raw_id: {
            "status": "complete", "thread_id": "thread_123",
            "draft_id": "draft_123",
        }},
    }), encoding="utf-8")
    review = seat.directory / "review"
    review.mkdir()
    (review / "latest.json").write_text(json.dumps({
        "messages": [{
            "opaque_message_id": opaque,
            "category": "recruiting", "confidence": "high",
            "recruit_profile": {
                "name": "Jordan Lee", "school": "North High",
                "position": "Center back", "location": "Boston, MA",
                "grad_year": "2028", "sender_type": "recruit",
            },
        }],
    }), encoding="utf-8")
    app = _app(tmp_path)
    response = _call(app, cookie=_login(app))

    assert "Jordan Lee" in response["body"]
    assert "North High" in response["body"]
    assert "Center back" in response["body"]
    assert "Class" in response["body"] and "2028" in response["body"]
    assert "#all/thread_123" in response["body"]
    assert raw_id not in response["body"]


def test_run_page_ignores_impossible_request_timestamp(tmp_path):
    now = dt.datetime(2026, 9, 9, 16, 0, tzinfo=dt.timezone.utc)
    connection.connect(tmp_path, "owner@example.test", now=now)
    app = _app(tmp_path, clock=lambda: now)
    response = _call(
        app, cookie=_login(app), query="run=checking&after=999999999999999999"
    )
    assert response["status"].startswith("200")
    assert "Refresh" not in response["headers"]


def test_undo_button_previews_and_queues_latest_recorded_run(tmp_path):
    seat = connection.connect(tmp_path, "owner@example.test")
    rollback = seat.directory / "rollback"
    rollback.mkdir()
    (rollback / "1788969600-00000.json").write_text(json.dumps({
        "version": 1, "group_id": "1788969600",
        "created_at": "2026-09-09T16:00:00+00:00",
        "completed_at": "2026-09-09T16:01:00+00:00", "undone_at": None,
        "entries": [{
            "message_id": "m1", "draft_id": "d1",
            "labels": ["Triage/Other", "Triage/Processed"],
            "draft_undone": False, "labels_undone": False,
        }],
    }), encoding="utf-8")
    calls = []

    def request_undo(root, *, group_id, confirmation, now):
        calls.append((root, group_id, confirmation, now))
        return 1788969600

    app = _app(tmp_path, undo_requester=request_undo)
    cookie = _login(app)
    dashboard = _call(app, cookie=cookie)
    assert "Undo drafts and labels" in dashboard["body"]
    assert "There is no item" in dashboard["body"]
    preview = _call(app, "/undo", cookie=cookie)
    assert "Type UNDO to continue" in preview["body"]
    response = _call(
        app, "/undo", "POST",
        urlencode({
            "csrf": app._csrf_value(), "group_id": "1788969600",
            "confirmation": "UNDO",
        }), cookie,
    )
    assert response["headers"]["Location"].startswith(
        "/?run=requested&undo=requested"
    )
    assert calls[0][1:3] == ("1788969600", "UNDO")


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
    assert "SameSite=Lax" in captured["headers"]["Set-Cookie"]
    assert queries == ["state=safe-state&code=one-time-code"]


def test_oauth_callback_explains_a_different_account_without_leaking_it(tmp_path):
    class CallbackProblem(RuntimeError):
        code = "account_mismatch"

    class Control:
        def complete_connect(self, _query):
            raise CallbackProblem("private provider detail")

    app = _app(tmp_path, control=Control())
    failed = _call(
        app, "/oauth/callback", query="state=safe-state&code=one-time-code"
    )
    assert failed["status"].startswith("303")
    assert failed["headers"]["Location"] == "/login?connect=account_mismatch"

    page = _call(app, "/login", query="connect=account_mismatch")
    assert "One Gmail account is already connected" in page["body"]
    assert "private provider detail" not in page["body"]


def test_login_explains_any_gmail_is_allowed_but_only_one_at_a_time(tmp_path):
    page = _call(_app(tmp_path, control=object()), "/login")
    assert "Connect any Gmail account" in page["body"]
    assert "supports one account at a time" in page["body"]


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


def test_disconnect_shows_the_real_mismatch_message(tmp_path):
    from hosted_control import HostedControlError

    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def disconnect(self, confirmation):
            raise HostedControlError(
                "type the connected Gmail address exactly to disconnect"
            )

    app = _app(tmp_path, control=Control())
    response = _call(
        app, "/disconnect", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": "wrong@example.test"}),
        _login(app),
    )
    assert response["status"].startswith("400")
    assert "type the connected Gmail address exactly" in response["body"]
    assert connection.current(tmp_path).account == address


def test_disconnect_does_not_blame_the_typed_address_for_an_unrelated_failure(
        tmp_path):
    """The same live regression, on the settings-page route this time - the
    one actually reported: typed correctly, refused anyway, blaming the
    address for an unrelated failure.
    """
    address = "owner@example.test"
    connection.connect(tmp_path, address)

    class Control:
        def disconnect(self, confirmation):
            raise RuntimeError("private KMS detail")

    app = _app(tmp_path, control=Control())
    response = _call(
        app, "/disconnect", "POST",
        urlencode({"csrf": app._csrf_value(), "confirmation": address}),
        _login(app),
    )
    assert response["status"].startswith("400")
    assert "type the connected gmail address exactly" not in response["body"].lower()
    assert "unexpectedly" in response["body"]
    assert "private KMS detail" not in response["body"]
    assert connection.current(tmp_path).account == address


def test_service_binds_to_loopback_and_runs_unprivileged():
    unit = open("hosted-dashboard.service.example", encoding="utf-8").read()
    assert "User=email-scanner" in unit
    assert "--bind 127.0.0.1:8081" in unit
    assert "--bind 0.0.0.0" not in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/mnt/state" in unit
    assert "--access-logfile /dev/null" in unit


def test_favicon_is_served_without_a_session(tmp_path):
    """The regression: browsers probe /favicon.ico on their own, unauthenticated.

    Before this route existed, an unrecognized path fell through to the
    session gate and got 303'd to /login - so a browser that fetched
    /favicon.ico directly (most do, independent of the <link> tag) received
    a redirect instead of an icon, and many browsers cache that failure
    stubbornly rather than retrying it after the page's <link> tag arrives.
    """
    app = _app(tmp_path)
    response = _call(app, "/favicon.ico")
    assert response["status"].startswith("200")
    assert not response["status"].startswith("303")
    assert response["headers"]["Content-Type"] == "image/svg+xml"


def test_favicon_body_matches_the_shared_source():
    from hosted_dashboard import FAVICON_SVG
    app = _app(Path("/tmp"))
    response = _call(app, "/favicon.ico")
    assert response["body"] == FAVICON_SVG


def test_favicon_is_cacheable_unlike_the_no_store_dashboard_pages(tmp_path):
    """A static, non-sensitive asset should not force a refetch on every load."""
    app = _app(tmp_path)
    response = _call(app, "/favicon.ico")
    assert "no-store" not in response["headers"]["Cache-Control"]
    assert "max-age" in response["headers"]["Cache-Control"]


def test_favicon_head_request_returns_no_body(tmp_path):
    app = _app(tmp_path)
    response = _call(app, "/favicon.ico", method="HEAD")
    assert response["status"].startswith("200")
    assert response["body"] == ""


def test_the_in_page_link_tag_uses_the_same_favicon_source(tmp_path):
    """Pins the two together so they cannot silently drift apart."""
    from hosted_dashboard import FAVICON_HREF
    app = _app(tmp_path)
    response = _call(app, "/login")
    assert f'href="{FAVICON_HREF}"' in response["body"]


def test_a_stray_query_string_on_favicon_still_serves_it(tmp_path):
    app = _app(tmp_path)
    response = _call(app, "/favicon.ico", query="v=2")
    assert response["status"].startswith("200")


def test_the_csp_allows_the_data_uri_favicon_to_actually_load(tmp_path):
    """The regression: default-src 'none' with no img-src override blocks
    every image load, including the <link rel="icon" href="data:..."> tag
    itself - silently, with no visible error on the page. A private window
    still showed no icon because of this, independent of any caching.
    """
    app = _app(tmp_path)
    response = _call(app, "/login")
    csp = response["headers"]["Content-Security-Policy"]
    assert "img-src 'self' data:" in csp
    assert "default-src 'none'" in csp


def test_the_favicon_href_scheme_is_actually_permitted_by_the_csp(tmp_path):
    """Pins the two together: the href really is a data: URI, and the
    policy really does allow that scheme for images."""
    from hosted_dashboard import FAVICON_HREF
    assert FAVICON_HREF.startswith("data:image/svg+xml,")
    app = _app(tmp_path)
    csp = _call(app, "/login")["headers"]["Content-Security-Policy"]
    img_src = next(part for part in csp.split(";") if "img-src" in part)
    assert "data:" in img_src
