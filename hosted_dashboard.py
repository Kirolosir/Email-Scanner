"""Authenticated human dashboard for the single hosted Gmail connection.

The machine-readable hosted_status endpoint remains small and address-free.
This separate surface is for the account owner: it shows the connected
address, schedule, safe run counts, and reviewed label names after an explicit
Google OAuth sign-in or operator-key fallback. It reads no token and imports
nothing from the Gmail, Gemini, or KMS stacks.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import json
import re
from pathlib import Path
from urllib.parse import parse_qs

import connection
import connection_schedule
import hosted_run_request
import hosted_settings
from hosted_status import HostedConfig, status_document


SESSION_COOKIE = "email_scanner_session"
MAX_FORM_BYTES = 8192
RUN_REFRESH_SECONDS = 4
MAX_RUN_FEEDBACK_AGE = dt.timedelta(days=2)
MAX_REVIEW_DRAFTS = 40
GMAIL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
COUNT_KEYS = (
    "scanned", "classified", "labeled", "drafted", "needs_review",
    "skipped", "failures", "deferred_draft_limit",
    "deferred_write_limit", "drafts_existing", "drafts_rebuilt",
    "no_reply_address", "fetch_failures", "generation_fallbacks",
    "retry_queued", "gmail_requests", "gmail_retries", "gmail_quota_units",
    "gemini_calls", "gemini_input_tokens", "gemini_output_tokens",
    "estimated_cost_microusd", "duration_seconds", "average_duration_seconds",
    "backup_verified", "backup_failures",
)

HTML_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )),
]

CONNECT_ERROR_MESSAGES = {
    "account_mismatch": (
        "One Gmail account is already connected. Continue with that account, "
        "then choose Sign out & disconnect before linking a different account."
    ),
    "consent_cancelled": (
        "Google access was cancelled or declined. Try again and approve the "
        "requested Gmail access."
    ),
    "state_expired": (
        "That Google sign-in expired. Start again and finish within ten minutes."
    ),
    "token_exchange_failed": (
        "Google could not finish issuing access. Start again in Chrome or Safari."
    ),
    "gmail_profile_failed": (
        "Google connected, but Gmail could not confirm the account. Make sure "
        "Gmail is available for the account you choose."
    ),
    "credential_storage_failed": (
        "Google approved access, but the secure connection could not be saved. "
        "Nothing was replaced; try again shortly."
    ),
    "configuration_failed": (
        "Google linking is temporarily unavailable because the site setup is "
        "incomplete."
    ),
    "start_failed": "Google sign-in could not start. Try again shortly.",
    "callback_invalid": "Google returned an incomplete sign-in. Start again.",
    "connect_failed": "Google sign-in did not finish. Try again.",
}


def _connect_error_code(error, fallback="connect_failed"):
    code = str(getattr(error, "code", "") or "")
    return code if code in CONNECT_ERROR_MESSAGES else fallback


def _escape(value, fallback="—"):
    value = str(value or "").strip()
    return html.escape(value[:300] if value else fallback)


def _read_json(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _safe_counts(active):
    document = _read_json(Path(active) / "daily-status.json") or {}
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}
    raw = run.get("counts")
    raw = raw if isinstance(raw, dict) else {}
    return {
        key: value for key in COUNT_KEYS
        if isinstance((value := raw.get(key)), int)
        and not isinstance(value, bool) and value >= 0
    }


def _safe_run_details(active):
    document = _read_json(Path(active) / "daily-status.json") or {}
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}
    raw_codes = run.get("safe_error_codes")
    raw_codes = raw_codes if isinstance(raw_codes, list) else []
    return {
        "outcome": str(run.get("outcome") or ""),
        "started_at": str(run.get("started_at") or ""),
        "finished_at": str(run.get("finished_at") or ""),
        "codes": {
            value for value in raw_codes
            if isinstance(value, str) and len(value) <= 80
        },
        "stage": str(run.get("stage") or "")[:80],
        "current": (
            run.get("current") if isinstance(run.get("current"), int)
            and not isinstance(run.get("current"), bool)
            and run.get("current") >= 0 else 0
        ),
        "total": (
            run.get("total") if isinstance(run.get("total"), int)
            and not isinstance(run.get("total"), bool)
            and run.get("total") >= 0 else 0
        ),
        "updated_at": str(run.get("updated_at") or ""),
    }


def _latest_review_report(active):
    review_dir = Path(active) / "review"
    try:
        candidates = sorted(
            (item for item in review_dir.glob("*.json") if item.is_file()),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return {}
    return _read_json(candidates[0]) if candidates else {}


def _safe_review_queue(active, limit=MAX_REVIEW_DRAFTS):
    """Join the private draft journal to bounded review metadata.

    Message bodies and generated draft text are never read. Raw Gmail ids are
    used only to build validated Gmail links and are not printed on the page.
    """
    state = _read_json(Path(active) / "daily-state.json") or {}
    messages = state.get("messages")
    messages = messages if isinstance(messages, dict) else {}
    report = _latest_review_report(active) or {}
    report_items = report.get("messages")
    report_items = report_items if isinstance(report_items, list) else []
    by_opaque = {
        item.get("opaque_message_id"): item for item in report_items
        if isinstance(item, dict)
        and isinstance(item.get("opaque_message_id"), str)
    }
    rows = []
    seen_drafts = set()
    for raw_message_id, record in reversed(list(messages.items())):
        if len(rows) >= limit:
            break
        if not isinstance(record, dict):
            continue
        draft_id = record.get("draft_id")
        thread_id = record.get("thread_id")
        if (not isinstance(draft_id, str) or not GMAIL_ID.fullmatch(draft_id)
                or draft_id in seen_drafts):
            continue
        seen_drafts.add(draft_id)
        context = by_opaque.get(
            hashlib.sha256(str(raw_message_id).encode("utf-8")).hexdigest()[:16],
            {},
        )
        recruit = context.get("recruit_profile")
        recruit = recruit if isinstance(recruit, dict) else {}
        rows.append({
            "status": str(record.get("status") or "draft_created")[:32],
            "thread_id": (
                thread_id if isinstance(thread_id, str)
                and GMAIL_ID.fullmatch(thread_id) else ""
            ),
            "category": str(context.get("category") or "unknown")[:80],
            "confidence": str(context.get("confidence") or "unknown")[:24],
            "recruit": {
                key: str(recruit.get(key) or "unknown")[:120]
                for key in (
                    "name", "school", "position", "location", "grad_year",
                    "sender_type",
                )
            },
        })
    return rows


def _timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value or ""))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _run_feedback(occupant, now, run_state="", requested_epoch=None):
    """Return human feedback and whether the page should refresh again."""
    if run_state == "invalid-count":
        return (
            '<p class="notice bad">Choose a whole number from 1 to '
            f'{hosted_run_request.MAX_HISTORY_MESSAGES} for the history scan.'
            '</p>', False,
        )
    if run_state == "already-running":
        return (
            '<p class="notice progress"><strong>A mailbox scan is already '
            'running.</strong> No duplicate scan was queued. This page will '
            'keep updating.</p>', True,
        )
    if run_state == "not-ready":
        return (
            '<p class="notice bad">The number is valid, but this inbox is not '
            'ready to scan yet. <a href="/settings">Finish inbox settings</a> '
            'first, then run the history scan again.</p>', False,
        )
    if run_state == "failed":
        return (
            '<p class="notice bad">The run could not be requested. Nothing '
            'was changed; try again shortly.</p>', False,
        )
    if occupant is None:
        return "", False

    details = _safe_run_details(occupant.directory)
    started = _timestamp(details["started_at"])
    finished = _timestamp(details["finished_at"])
    authorized = _timestamp(occupant.last_authorized_at)
    auth_error_is_current = (
        "gmail_reauthorization_required" in details["codes"]
        and not (authorized and finished and authorized > finished)
    )
    if auth_error_is_current:
        return (
            '<p class="notice bad"><strong>Google needs to be reconnected.</strong> '
            'Use Link Google account, then press Run now again.</p>', False,
        )

    if run_state not in {"requested", "checking"} or requested_epoch is None:
        return "", False
    requested = dt.datetime.fromtimestamp(
        requested_epoch, tz=dt.timezone.utc
    )
    current = now.astimezone(dt.timezone.utc)
    age = max(dt.timedelta(), current - requested)
    is_current_run = bool(started and started >= requested - dt.timedelta(seconds=2))
    can_refresh = age <= MAX_RUN_FEEDBACK_AGE

    if is_current_run and details["outcome"] == "running":
        return (
            '<p class="notice progress"><strong>Run in progress.</strong> '
            'This page will update automatically; larger inboxes can take a '
            'few minutes.</p>', can_refresh,
        )
    if is_current_run and details["outcome"] == "success":
        return (
            '<p class="notice good"><strong>Run complete.</strong> The latest '
            'counts are shown below.</p>', False,
        )
    if is_current_run and details["outcome"] == "failed":
        return (
            '<p class="notice bad"><strong>The run stopped safely.</strong> '
            'No email was sent. Reconnect Google or review your settings, then '
            'try again.</p>', False,
        )

    queued = hosted_run_request.request_path(occupant.directory).is_file()
    if queued or (age <= dt.timedelta(seconds=30) and can_refresh):
        return (
            '<p class="notice progress"><strong>Starting your run…</strong> '
            'You can leave this page; it will update automatically.</p>', True,
        )
    if can_refresh:
        return (
            '<p class="notice progress"><strong>Still waiting for the run.</strong> '
            'The page will keep checking automatically.</p>', True,
        )
    return (
        '<p class="notice bad"><strong>The run is taking longer than expected.'
        '</strong> Reconnect Google, then try Run now again.</p>', False,
    )


def _safe_labels(active):
    document = _read_json(Path(active) / "account.json") or {}
    taxonomy = document.get("taxonomy")
    taxonomy = taxonomy if isinstance(taxonomy, list) else []
    labels = []
    for item in taxonomy:
        if not isinstance(item, dict):
            continue
        name = item.get("label")
        display = item.get("display")
        drafting = item.get("drafting")
        drafting = drafting if isinstance(drafting, dict) else {}
        if isinstance(name, str) and name.strip():
            labels.append({
                "name": name.strip()[:225],
                "display": str(display or name).strip()[:128],
                "drafting": drafting.get("mode") == "generic",
            })
    return labels


def _safe_coach_profile(active):
    document = _read_json(Path(active) / "account.json") or {}
    ai = document.get("ai_drafting")
    ai = ai if isinstance(ai, dict) else {}
    return {
        key: str(ai.get(key) or "")[:limit]
        for key, limit in {
            "display_name": 120,
            "role": 120,
            "organization": 160,
            "default_guidance": 1200,
        }.items()
    }


FAILURE_MESSAGES = {
    "gmail_reauthorization_required": "Reconnect Google, then run the scan again.",
    "required_labels_missing": "Save the label settings again, then retry.",
    "message_fetch_failed": "Some Gmail messages could not be read. Retry the run.",
    "history_chunk_failed": "The history scan paused. Completed work was saved.",
    "account_setup_incomplete": "Finish the coach profile and label settings.",
    "label_setup_failed": "Gmail labels could not be prepared. Save settings again.",
    "label_setup_invalid": "The saved label plan needs to be refreshed.",
}


def _render_run_progress(details):
    if details.get("outcome") != "running":
        return ""
    current = details.get("current", 0)
    total = details.get("total", 0)
    percent = round((current / total) * 100) if total else 0
    stage = _escape(details.get("stage"), "Working")
    amount = f"{current} of {total}" if total else "Preparing"
    return f"""
      <section class="panel run-progress" aria-live="polite">
        <div class="section-head"><div><p class="eyebrow">Live run</p>
          <h2>{stage}</h2></div><strong>{html.escape(amount)}</strong></div>
        <progress max="{max(1, total)}" value="{min(current, max(1, total))}">{percent}%</progress>
        <p>{percent}% complete · updates every {RUN_REFRESH_SECONDS} seconds.</p>
      </section>"""


def _render_failure_alert(details):
    if details.get("outcome") != "failed":
        return ""
    messages = [
        FAILURE_MESSAGES.get(code, "Review the latest run and try again.")
        for code in sorted(details.get("codes") or ())
    ]
    action = messages[0] if messages else "Review the settings, then retry the run."
    return f"""
      <section class="failure-alert" role="alert">
        <div><p class="eyebrow">Run needs attention</p>
          <h2>The last scan stopped safely</h2>
          <p>{html.escape(action)} No email was sent.</p></div>
        <a class="secondary" href="/settings">Review settings</a>
      </section>"""


def _render_review_queue(rows):
    if not rows:
        return (
            '<p class="empty">No generated drafts are waiting yet. They will '
            'appear here after a scan.</p>'
        )
    cards = []
    for row in rows:
        thread_id = row.get("thread_id")
        gmail_url = (
            f"https://mail.google.com/mail/u/0/#all/{thread_id}"
            if thread_id else "https://mail.google.com/mail/u/0/#drafts"
        )
        recruit = row.get("recruit") or {}
        details = []
        for key, label in (
            ("name", "Recruit"), ("grad_year", "Class"),
            ("position", "Position"), ("school", "School / club"),
            ("location", "Location"),
        ):
            value = str(recruit.get(key) or "unknown")
            if value.casefold() != "unknown":
                details.append(
                    f'<span><small>{label}</small>{_escape(value)}</span>'
                )
        insight = (
            '<div class="recruit-fields">' + "".join(details) + "</div>"
            if details else
            '<p class="field-note">No recruiting details were stated clearly.</p>'
        )
        cards.append(f"""
          <article class="draft-card">
            <div class="draft-card-head"><div>
              <span class="tag">{_escape(row.get('category'), 'Other')}</span>
              <span class="confidence">{_escape(row.get('confidence'), 'unknown')} confidence</span>
            </div><a class="secondary" href="{html.escape(gmail_url)}"
              target="_blank" rel="noopener noreferrer">Review in Gmail</a></div>
            {insight}
            <p class="verify-note">Automatically extracted details · verify against the email before sending.</p>
          </article>""")
    return "".join(cards)


def _cookie_map(environ):
    result = {}
    for part in str(environ.get("HTTP_COOKIE", "")).split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key:
            result[key] = value
    return result


class HostedDashboardApp:
    def __init__(self, config, clock=None, control=None, run_requester=None):
        self.config = config
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.control = control
        self.run_requester = run_requester or hosted_run_request.request_run

    def _session_value(self):
        return hmac.new(
            self.config._operator_bearer.encode("utf-8"),
            b"email-scanner-dashboard-session-v1",
            hashlib.sha256,
        ).hexdigest()

    def _session_ok(self, environ):
        presented = _cookie_map(environ).get(SESSION_COOKIE, "")
        return hmac.compare_digest(self._session_value(), presented)

    def _session_cookie(self, clear=False):
        secure = "; Secure" if self.config.require_forwarded_https else ""
        value = "" if clear else self._session_value()
        maximum = "; Max-Age=0" if clear else ""
        return (
            f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax"
            f"{secure}{maximum}"
        )

    def _csrf_value(self):
        return hmac.new(
            self.config._operator_bearer.encode("utf-8"),
            b"email-scanner-dashboard-csrf-v1",
            hashlib.sha256,
        ).hexdigest()

    def _csrf_ok(self, form):
        return hmac.compare_digest(
            self._csrf_value(), str(form.get("csrf", ""))
        )

    def _https_ok(self, environ):
        if not self.config.require_forwarded_https:
            return True
        forwarded = environ.get("HTTP_X_FORWARDED_PROTO", "")
        return forwarded.split(",")[0].strip().lower() == "https"

    @staticmethod
    def _respond(start_response, status, body, headers=(), head=False):
        payload = body.encode("utf-8")
        response_headers = list(HTML_HEADERS) + list(headers)
        response_headers.append(("Content-Length", str(len(payload))))
        start_response(status, response_headers)
        return [b"" if head else payload]

    @staticmethod
    def _redirect(start_response, location, headers=()):
        response_headers = list(HTML_HEADERS) + list(headers) + [
            ("Location", location), ("Content-Length", "0")
        ]
        start_response("303 See Other", response_headers)
        return [b""]

    @staticmethod
    def _form(environ):
        try:
            length = int(environ.get("CONTENT_LENGTH", "0") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_FORM_BYTES:
            return None
        raw = environ.get("wsgi.input").read(length)
        try:
            values = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            return None
        return {key: entries[-1] for key, entries in values.items() if entries}

    def __call__(self, environ, start_response):
        try:
            return self._route(environ, start_response)
        except Exception:  # noqa: BLE001 - private detail stays server-side
            return self._respond(
                start_response, "500 Internal Server Error",
                self._page("Something went wrong", (
                    '<section class="panel"><h1>Dashboard unavailable</h1>'
                    '<p>Nothing was changed. Try again shortly.</p></section>'
                )),
            )

    def _route(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "") or "/"
        head = method == "HEAD"

        if not self._https_ok(environ):
            return self._respond(
                start_response, "400 Bad Request",
                self._page("HTTPS required", "<h1>HTTPS is required.</h1>"),
                head=head,
            )

        # OAuth state is the callback's authentication, so this route must be
        # handled before the ordinary dashboard-session gate. The resulting
        # Lax cookie is available on the top-level redirect back to this site.
        if path == "/oauth/callback" and method == "GET":
            if self.control is None:
                return self._redirect(
                    start_response, "/login?connect=configuration_failed"
                )
            try:
                self.control.complete_connect(environ.get("QUERY_STRING", ""))
            except Exception as exc:  # noqa: BLE001 - only safe code reaches HTML
                code = _connect_error_code(exc)
                return self._redirect(
                    start_response, f"/login?connect={code}"
                )
            return self._redirect(
                start_response, "/?connected=1",
                [("Set-Cookie", self._session_cookie())],
            )

        if path == "/login" and method in {"GET", "HEAD"}:
            query = parse_qs(
                str(environ.get("QUERY_STRING", "")), keep_blank_values=True
            )
            return self._respond(
                start_response, "200 OK",
                self._login_page(
                    connect_error=(query.get("connect") or [""])[-1],
                    signed_out=query.get("signed_out") == ["1"],
                ),
                head=head,
            )
        if path == "/login" and method == "POST":
            form = self._form(environ)
            if form is None:
                return self._respond(
                    start_response, "400 Bad Request", self._login_page(True)
                )
            if not self.config.bearer_matches(form.get("access_key", "")):
                return self._respond(
                    start_response, "401 Unauthorized", self._login_page(True)
                )
            return self._redirect(
                start_response, "/", [("Set-Cookie", self._session_cookie())]
            )

        # Google OAuth is the normal sign-in path, so it must be startable from
        # the login page before a dashboard session exists. The hidden token is
        # still required, and the OAuth callback's one-time state is the second
        # request-binding layer.
        if path == "/connect" and method in {"GET", "POST"}:
            if method == "GET":
                values = parse_qs(
                    str(environ.get("QUERY_STRING", "")),
                    keep_blank_values=True,
                )
                form = {
                    key: entries[-1]
                    for key, entries in values.items() if entries
                }
            else:
                form = self._form(environ)
            if form is None or not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            if self.control is None:
                return self._redirect(
                    start_response, "/login?connect=configuration_failed"
                )
            try:
                location = self.control.begin_connect()
            except Exception as exc:  # noqa: BLE001 - only safe code reaches HTML
                code = _connect_error_code(exc, "start_failed")
                return self._redirect(
                    start_response, f"/login?connect={code}"
                )
            return self._redirect(start_response, location)

        if not self._session_ok(environ):
            return self._redirect(start_response, "/login")

        if path in {"/run-now", "/run-history"} and method == "POST":
            form = self._form(environ)
            if form is None or not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            try:
                if path == "/run-history":
                    raw_count = str(form.get("message_count", "")).strip()
                    history_count = int(raw_count)
                    if not 1 <= history_count <= \
                            hosted_run_request.MAX_HISTORY_MESSAGES:
                        raise ValueError("history count is outside the safe range")
                    requested_epoch = self.run_requester(
                        self.config.state_root, now=self.clock(),
                        history_count=history_count,
                    )
                else:
                    requested_epoch = self.run_requester(
                        self.config.state_root, now=self.clock()
                    )
            except hosted_run_request.RunAlreadyActive:
                try:
                    active_occupant = connection.current(self.config.state_root)
                    active_details = (
                        _safe_run_details(active_occupant.directory)
                        if active_occupant is not None else {}
                    )
                    active_started = _timestamp(active_details.get("started_at"))
                except connection.ConnectionConfigError:
                    active_started = None
                active_epoch = int(
                    (active_started or self.clock()).timestamp()
                )
                return self._redirect(
                    start_response,
                    f"/?run=already-running&after={active_epoch}",
                )
            except ValueError:
                if path == "/run-history":
                    return self._redirect(start_response, "/?run=invalid-count")
                return self._redirect(start_response, "/?run=not-ready")
            except hosted_run_request.RunRequestError:
                return self._redirect(start_response, "/?run=not-ready")
            except (connection.ConnectionError,
                    connection.ConnectionConfigError, OSError):
                return self._redirect(start_response, "/?run=failed")
            if not isinstance(requested_epoch, int):
                requested_epoch = int(self.clock().timestamp())
            return self._redirect(
                start_response,
                f"/?run=requested&after={requested_epoch}",
            )

        if path == "/logout" and method == "POST":
            form = self._form(environ)
            if form is None or not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            try:
                occupant = connection.current(self.config.state_root)
            except connection.ConnectionConfigError:
                occupant = None
            if occupant is not None:
                if self.control is None:
                    return self._respond(
                        start_response, "503 Service Unavailable",
                        self._signout_page(
                            occupant, "Gmail disconnect is temporarily unavailable."
                        ),
                    )
                try:
                    self.control.disconnect(form.get("confirmation", ""))
                except Exception:  # noqa: BLE001 - keep provider detail private
                    try:
                        occupant = connection.current(self.config.state_root)
                    except connection.ConnectionConfigError:
                        occupant = None
                    if occupant is not None:
                        return self._respond(
                            start_response, "400 Bad Request",
                            self._signout_page(
                                occupant,
                                "Sign out was refused. Type the connected Gmail "
                                "address exactly.",
                            ),
                        )
            return self._redirect(
                start_response, "/login?signed_out=1",
                [("Set-Cookie", self._session_cookie(clear=True))],
            )

        if path == "/signout" and method in {"GET", "HEAD"}:
            try:
                occupant = connection.current(self.config.state_root)
            except connection.ConnectionConfigError:
                occupant = None
            return self._respond(
                start_response, "200 OK", self._signout_page(occupant),
                head=head,
            )

        if path == "/" and method in {"GET", "HEAD"}:
            query = parse_qs(
                str(environ.get("QUERY_STRING", "")), keep_blank_values=True
            )
            run_state = (query.get("run") or [""])[-1]
            route_now = self.clock()
            try:
                requested_epoch = int((query.get("after") or [""])[-1])
            except (TypeError, ValueError):
                requested_epoch = None
            latest_reasonable_epoch = int(route_now.timestamp()) + 300
            if (
                requested_epoch is not None
                and not 0 <= requested_epoch <= latest_reasonable_epoch
            ):
                requested_epoch = None
            try:
                feedback_occupant = connection.current(self.config.state_root)
            except connection.ConnectionConfigError:
                feedback_occupant = None
            run_notice, refresh = _run_feedback(
                feedback_occupant, route_now, run_state, requested_epoch
            )
            headers = []
            if refresh and requested_epoch is not None:
                headers.append((
                    "Refresh",
                    f"{RUN_REFRESH_SECONDS}; url=/?run=checking&after={requested_epoch}",
                ))
            elif feedback_occupant is not None and _safe_run_details(
                    feedback_occupant.directory).get("outcome") == "running":
                headers.append(("Refresh", f"{RUN_REFRESH_SECONDS}; url=/"))
            return self._respond(
                start_response, "200 OK",
                self._dashboard(
                    saved=query.get("saved") == ["1"],
                    connected=query.get("connected") == ["1"],
                    disconnected=query.get("disconnected") == ["1"],
                    connect_failed=query.get("connect") == ["failed"],
                    run_notice=run_notice,
                ),
                headers=headers,
                head=head,
            )
        if path == "/settings" and method in {"GET", "HEAD"}:
            try:
                occupant = connection.current(self.config.state_root)
            except connection.ConnectionConfigError:
                occupant = None
            if occupant is None:
                return self._redirect(start_response, "/")
            return self._respond(
                start_response, "200 OK", self._settings_page(occupant),
                head=head,
            )
        if path == "/settings" and method == "POST":
            form = self._form(environ)
            if form is None:
                return self._respond(
                    start_response, "400 Bad Request",
                    self._page(
                        "Settings not saved",
                        '<main class="login-shell"><section class="login-card">'
                        '<h1>Settings not saved</h1><p>The form was too large '
                        'or unreadable.</p><a class="secondary" href="/settings">'
                        'Return to settings</a></section></main>',
                    ),
                )
            if not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            occupant = None
            try:
                occupant = connection.current(self.config.state_root)
                if occupant is None:
                    return self._redirect(start_response, "/")
                hosted_settings.save_settings(self.config.state_root, form)
            except hosted_settings.SettingsError as exc:
                return self._respond(
                    start_response, "400 Bad Request",
                    self._settings_page(occupant, form=form, error=str(exc)),
                )
            except (connection.ConnectionError,
                    connection.ConnectionConfigError):
                if occupant is None:
                    return self._respond(
                        start_response, "409 Conflict",
                        self._page(
                            "Settings unavailable",
                            '<main class="login-shell"><section class="login-card">'
                            '<h1>Settings unavailable</h1><p>Nothing was changed.'
                            '</p><a class="secondary" href="/">Return to dashboard'
                            '</a></section></main>',
                        ),
                    )
                return self._respond(
                    start_response, "409 Conflict",
                    self._settings_page(
                        occupant, form=form,
                        error="settings could not be saved; nothing was activated",
                    ),
                )
            return self._redirect(start_response, "/?saved=1")
        if path == "/disconnect" and method == "POST":
            form = self._form(environ)
            if form is None or not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            if self.control is None:
                return self._redirect(start_response, "/?connect=failed")
            try:
                self.control.disconnect(form.get("confirmation", ""))
            except Exception:  # noqa: BLE001 - KMS/revocation detail stays private
                try:
                    occupant = connection.current(self.config.state_root)
                except connection.ConnectionConfigError:
                    occupant = None
                if occupant is None:
                    return self._redirect(start_response, "/")
                return self._respond(
                    start_response, "400 Bad Request",
                    self._settings_page(
                        occupant, error=(
                            "disconnect was refused; type the connected Gmail "
                            "address exactly"
                        ),
                    ),
                )
            return self._redirect(start_response, "/?disconnected=1")
        if method not in {"GET", "HEAD", "POST"}:
            return self._respond(
                start_response, "405 Method Not Allowed",
                self._page("Method refused", "<h1>Method refused.</h1>"),
            )
        return self._respond(
            start_response, "404 Not Found",
            self._page("Not found", "<h1>Page not found.</h1>"),
            head=head,
        )

    def _login_page(self, failed=False, connect_error="", signed_out=False):
        if failed and not connect_error:
            connect_error = "connect_failed"
        connect_notice = (
            '<p class="notice bad">'
            + html.escape(CONNECT_ERROR_MESSAGES.get(
                connect_error, CONNECT_ERROR_MESSAGES["connect_failed"]
            ))
            + '</p>'
            if connect_error else ""
        )
        if signed_out:
            connect_notice = (
                '<p class="notice good">Signed out. Google access was revoked '
                'when available, the stored Gmail credential was removed, and '
                'the account slot is ready for a different Gmail account.</p>'
            )
        google_link = ""
        if self.control is not None:
            try:
                location = self.control.begin_connect()
                google_link = (
                    f'<a class="google-button" href="{html.escape(location)}">'
                    '<span aria-hidden="true">G</span>Continue with Google</a>'
                )
            except Exception as exc:  # noqa: BLE001 - render only safe text
                if not connect_error:
                    code = _connect_error_code(exc, "start_failed")
                    connect_notice = (
                        '<p class="notice bad">'
                        + html.escape(CONNECT_ERROR_MESSAGES[code])
                        + '</p>'
                    )
        return self._page("Sign in", f"""
          <main class="login-shell">
            <section class="login-card">
              <div class="mark">ES</div>
              <p class="eyebrow">Email Scanner</p>
              <h1>Continue with Google</h1>
              <p class="lede">Connect any Gmail account. This installation
              supports one account at a time.</p>
              {connect_notice}
              {google_link}
              <p class="browser-note">Google returns you to the dashboard in
              this same browser. If this page is inside another app, open it
              in Chrome or Safari first.</p>
            </section>
          </main>
        """)

    def _dashboard(self, saved=False, connected=False, disconnected=False,
                   connect_failed=False, run_notice=""):
        just_connected = connected
        now = self.clock()
        public = status_document(self.config.state_root, now)
        state = public.get("connection", {})
        try:
            occupant = connection.current(self.config.state_root)
        except connection.ConnectionConfigError:
            occupant = None

        if occupant is None:
            account = "No Gmail account connected"
            next_run = "—"
            labels = []
            counts = {}
            run_details = {}
            review_rows = []
            coach_profile = {}
        else:
            account = occupant.account
            next_run = connection_schedule.next_run(occupant, now).strftime(
                "%a, %b %-d at %-I:%M %p %Z"
            )
            labels = _safe_labels(occupant.directory)
            counts = _safe_counts(occupant.directory)
            run_details = _safe_run_details(occupant.directory)
            review_rows = _safe_review_queue(occupant.directory)
            coach_profile = _safe_coach_profile(occupant.directory)

        expiry = public.get("expiry") or {}
        last = public.get("last_run") or {}
        connected = state.get("state") == "connected"
        status_tone = "good" if connected else "warn"
        status_text = "Active" if connected else state.get("state", "Vacant")
        progress_panel = _render_run_progress(run_details)
        failure_alert = _render_failure_alert(run_details)
        review_queue = _render_review_queue(review_rows)
        coach_name = coach_profile.get("display_name") or "Coach profile"
        coach_context = " · ".join(
            value for value in (
                coach_profile.get("role"), coach_profile.get("organization")
            ) if value
        ) or "Add your role and program so replies sound like you."

        count_labels = {
            "drafted": "drafts created",
            "drafts_existing": "existing drafts preserved",
            "drafts_rebuilt": "missing drafts rebuilt",
            "no_reply_address": "no reply address",
            "fetch_failures": "email retrieval failures",
            "generation_fallbacks": "generation fallbacks",
            "retry_queued": "queued for retry",
            "gmail_requests": "Gmail requests",
            "gmail_retries": "Gmail retries",
            "gmail_quota_units": "Gmail quota units",
            "gemini_calls": "model calls",
            "gemini_input_tokens": "input tokens",
            "gemini_output_tokens": "output tokens",
            "estimated_cost_microusd": "estimated cost (millionths of $)",
            "duration_seconds": "run time (seconds)",
            "average_duration_seconds": "average run time (seconds)",
            "backup_verified": "verified backups",
            "backup_failures": "backup failures",
        }
        coverage_keys = {
            "drafted", "drafts_existing", "drafts_rebuilt",
            "no_reply_address", "fetch_failures", "generation_fallbacks",
            "retry_queued",
        }
        usage_keys = {
            "gmail_requests", "gmail_retries", "gmail_quota_units",
            "gemini_calls", "gemini_input_tokens", "gemini_output_tokens",
            "estimated_cost_microusd", "duration_seconds",
            "average_duration_seconds", "backup_verified", "backup_failures",
        }

        def metric_cards(keys):
            cards = []
            for key, value in counts.items():
                if key not in keys:
                    continue
                displayed = (
                    f"${value / 1_000_000:.4f}"
                    if key == "estimated_cost_microusd" else str(value)
                )
                cards.append(
                    f'<div class="metric"><span>{_escape(count_labels.get(key, key.replace("_", " ")))}</span>'
                    f'<strong>{_escape(displayed)}</strong></div>'
                )
            return "".join(cards) or (
                '<p class="empty">Results will appear after the first run.</p>'
            )

        count_cards = "".join(
            f'<div class="metric"><span>{_escape(count_labels.get(key, key.replace("_", " ")))}</span>'
            f'<strong>{value}</strong></div>'
            for key, value in counts.items()
            if key not in coverage_keys | usage_keys
        ) or '<p class="empty">Results will appear after the first run.</p>'
        coverage_cards = metric_cards(coverage_keys)
        usage_cards = metric_cards(usage_keys)
        label_rows = "".join(
            '<li><div><strong>' + _escape(item["display"]) + '</strong>'
            '<span>' + _escape(item["name"]) + '</span></div>'
            '<span class="tag">' + (
                "labels + drafts" if item["drafting"] else "labels only"
            ) + '</span></li>'
            for item in labels
        ) or '<li class="empty">Label setup is not finished yet.</li>'

        saved_notice = (
            '<p class="notice good">Settings saved. The reviewed Gmail labels '
            'will be prepared before the next daily run.</p>' if saved else ""
        )
        connection_notice = ""
        if just_connected:
            connection_notice = (
                '<p class="notice good">Gmail connected securely. Review your '
                'labels and schedule before the first daily run.</p>'
            )
        elif disconnected:
            connection_notice = (
                '<p class="notice good">Gmail was removed. The local credential '
                'was destroyed and account records were archived.</p>'
            )
        elif connect_failed:
            connection_notice = (
                '<p class="notice bad">Google sign-in did not finish. Nothing '
                'new was connected; you can try again.</p>'
            )
        settings_link = (
            '<a class="secondary" href="/settings">Edit labels &amp; schedule</a>'
            if occupant is not None else ""
        )
        connect_form = f"""
          <form method="post" action="/connect">
            <input type="hidden" name="csrf" value="{self._csrf_value()}">
            <button class="ghost" type="submit">Link Google account</button>
          </form>""" if self.control is not None else ""
        run_form = f"""
          <form method="post" action="/run-now">
            <input type="hidden" name="csrf" value="{self._csrf_value()}">
            <button type="submit">Scan new mail</button>
          </form>""" if occupant is not None else """
          <button type="button" disabled title="Link Google first">Scan new mail</button>"""
        history_form = f"""
          <section class="panel history-run">
            <div><p class="eyebrow">Inbox catch-up</p>
              <h2>Scan previous emails</h2>
              <p>Choose how many of the newest eligible messages to check.
              Every message with a usable reply address ends with one unsent
              draft. Existing drafts are kept, and deleted program drafts are
              rebuilt instead of being silently skipped.
              Larger batches take longer because every reply is written
              individually; 5,000 messages can run for many hours.</p></div>
            <form method="post" action="/run-history">
              <input type="hidden" name="csrf" value="{self._csrf_value()}">
              <label for="message_count">Previous messages</label>
              <div class="history-controls"><input id="message_count"
                name="message_count" type="number" min="1"
                max="{hosted_run_request.MAX_HISTORY_MESSAGES}"
                value="{min(50, hosted_run_request.MAX_HISTORY_MESSAGES)}"
                required><button type="submit">Scan previous emails</button></div>
            </form>
          </section>""" if occupant is not None else ""

        return self._page("Dashboard", f"""
          <header class="topbar">
            <a class="brand" href="/"><span class="mark small">ES</span>
              <span>Email Scanner</span></a>
            <a class="ghost-link" href="/signout">Sign out &amp; disconnect</a>
          </header>
          <main class="workspace">
            {saved_notice}
            {connection_notice}
            {run_notice}
            {failure_alert}
            <section class="account-hero">
              <div>
                <p class="eyebrow">Connected inbox</p>
                <h1>{_escape(account)}</h1>
                <p class="lede">Gemini organizes eligible mail and prepares
                unsent Gmail drafts for review. Nothing is auto-sent.</p>
              </div>
              <div class="hero-actions"><span class="status {status_tone}"><i></i>{_escape(status_text)}</span>
                {connect_form}{run_form}</div>
            </section>

            {progress_panel}

            <section class="overview-grid">
              <article class="panel schedule">
                <p class="eyebrow">Next daily run</p>
                <h2>{_escape(next_run)}</h2>
                <p>Up to {_escape(state.get("limits", {}).get("max_scan"))}
                recent messages per run. Every eligible message in the batch
                is labeled and drafted.</p>
              </article>
              <article class="panel health">
                <p class="eyebrow">Gmail connection</p>
                <h2>{_escape(expiry.get("summary"), "Waiting for connection")}</h2>
                <p>Last authorized {_escape(state.get("last_authorized_at"))}</p>
              </article>
              <article class="panel last-run">
                <p class="eyebrow">Last run</p>
                <h2>{_escape(last.get("outcome"), "Not run yet")}</h2>
                <p>{_escape(last.get("finished_at"), "No completed run yet")}</p>
              </article>
            </section>

            {history_form}

            <section class="content-grid">
              <article class="panel results">
                <div class="section-head"><div><p class="eyebrow">Activity</p>
                  <h2>Latest run results</h2></div></div>
                <div class="metrics">{count_cards}</div>
              </article>
              <article class="panel labels">
                <div class="section-head"><div><p class="eyebrow">Rules</p>
                  <h2>Your Gmail labels</h2></div>
                  <div class="section-actions"><span class="count-badge">{len(labels)}</span>
                  {settings_link}</div></div>
                <ul>{label_rows}</ul>
              </article>
            </section>

            <section class="content-grid">
              <article class="panel results">
                <div class="section-head"><div><p class="eyebrow">Coverage</p>
                  <h2>Draft coverage</h2></div></div>
                <div class="metrics">{coverage_cards}</div>
              </article>
              <article class="panel results">
                <div class="section-head"><div><p class="eyebrow">Reliability</p>
                  <h2>Usage and recovery</h2></div></div>
                <div class="metrics">{usage_cards}</div>
              </article>
            </section>

            <section class="panel coach-card">
              <div><p class="eyebrow">Coach voice</p>
                <h2>{_escape(coach_name)}</h2>
                <p>{_escape(coach_context)}</p></div>
              {settings_link}
            </section>

            <section class="panel review-queue">
              <div class="section-head"><div><p class="eyebrow">Review queue</p>
                <h2>Recruit replies ready in Gmail</h2>
                <p>Review, edit, and send each response from Gmail. Nothing
                leaves Drafts automatically.</p></div>
                <a class="secondary" href="https://mail.google.com/mail/u/0/#drafts"
                  target="_blank" rel="noopener noreferrer">Open all drafts</a></div>
              <div class="draft-list">{review_queue}</div>
            </section>
          </main>
        """)

    @staticmethod
    def _settings_values(occupant):
        document = _read_json(Path(occupant.directory) / "account.json") or {}
        taxonomy = document.get("taxonomy")
        taxonomy = taxonomy if isinstance(taxonomy, list) else []
        lines = []
        for item in taxonomy:
            if not isinstance(item, dict):
                continue
            display = str(item.get("display", "")).strip()
            label = str(item.get("label", "")).strip()
            if display and label:
                lines.append(f"{display} | {label}")
        ai = document.get("ai_drafting")
        ai = ai if isinstance(ai, dict) else {}
        return {
            "labels": "\n".join(lines) or (
                "Action needed | Action Needed\n"
                "Scheduling | Scheduling\n"
                "Finance | Finance\n"
                "Newsletters | Newsletters\n"
                "Other | Other"
            ),
            "timezone": str(document.get("timezone")
                            or occupant.timezone_name),
            "run_at": occupant.run_at,
            "display_name": str(ai.get("display_name", "")),
            "role": str(ai.get("role", "")),
            "organization": str(ai.get("organization", "")),
            "signature": str(ai.get("signature", "")),
            "draft_guidance": str(
                ai.get("default_guidance")
                or hosted_settings.DEFAULT_DRAFT_GUIDANCE
            ),
            "max_scan": str(occupant.max_scan),
            "limit": str(occupant.limit),
            "max_drafts": str(occupant.max_drafts),
        }

    def _settings_page(self, occupant, form=None, error=""):
        values = dict(form) if form is not None else self._settings_values(occupant)
        fields = {
            key: html.escape(str(values.get(key, ""))) for key in (
                "labels", "timezone", "run_at", "display_name", "signature",
                "role", "organization", "draft_guidance", "max_scan", "limit",
                "max_drafts",
            )
        }
        error_notice = (
            f'<p class="notice bad">{html.escape(str(error))}</p>' if error else ""
        )
        return self._page("Settings", f"""
          <header class="topbar">
            <a class="brand" href="/"><span class="mark small">ES</span>
              <span>Email Scanner</span></a>
            <div class="top-actions"><a class="ghost-link" href="/">Dashboard</a>
              <a class="ghost-link" href="/signout">Sign out &amp; disconnect</a>
            </div>
          </header>
          <main class="workspace settings-shell">
            <section class="account-hero compact">
              <div><p class="eyebrow">Inbox settings</p>
                <h1>Shape your daily assistant</h1>
                <p class="lede">Choose the labels, schedule, and batch size
                for {_escape(occupant.account)}.</p></div>
            </section>
            {error_notice}
            <form class="settings-form" method="post" action="/settings">
              <input type="hidden" name="csrf" value="{self._csrf_value()}">
              <section class="panel form-section">
                <div class="form-copy"><p class="eyebrow">1 · Organize</p>
                  <h2>Gmail labels</h2><p>Enter one label per line. Use
                  <strong>Display name | Gmail label</strong>. “Other” is added
                  automatically if omitted.</p></div>
                <div><label for="labels">Labels, up to 12</label>
                  <textarea id="labels" name="labels" rows="8" required
                    spellcheck="false">{fields['labels']}</textarea>
                  <p class="field-note">Example: Scheduling | Scheduling</p></div>
              </section>
              <section class="panel form-section">
                <div class="form-copy"><p class="eyebrow">2 · Schedule</p>
                  <h2>Daily run</h2><p>This local time controls when the
                  assistant checks eligible inbox mail.</p></div>
                <div class="field-grid">
                  <div><label for="run_at">Start time</label><input id="run_at"
                    name="run_at" type="time" value="{fields['run_at']}" required></div>
                  <div><label for="timezone">Timezone</label><input id="timezone"
                    name="timezone" value="{fields['timezone']}" required
                    autocomplete="off"><p class="field-note">Use an IANA
                    city-based timezone name or UTC.</p></div>
                  <div><label for="max_scan">Messages scanned</label><input
                    id="max_scan" name="max_scan" type="number" min="1"
                    max="{hosted_settings.MAX_MESSAGES_PER_RUN}"
                    value="{fields['max_scan']}" required>
                    <p class="field-note">Every eligible message in this
                    batch receives a label and an unsent draft.</p></div>
                </div>
              </section>
              <section class="panel form-section">
                <div class="form-copy"><p class="eyebrow">3 · Coach profile</p>
                  <h2>Your voice and program</h2><p>Give the assistant enough
                  context to sound like you while replying to recruits.
                  Every result remains an unsent Gmail draft.</p></div>
                <div><label for="display_name">Your name</label><input
                  id="display_name" name="display_name" maxlength="120"
                  value="{fields['display_name']}" required>
                  <div class="field-grid coach-fields">
                    <div><label for="role">Role</label><input id="role"
                      name="role" maxlength="120" value="{fields['role']}"
                      placeholder="Head Men's Soccer Coach"></div>
                    <div><label for="organization">School or program</label><input
                      id="organization" name="organization" maxlength="160"
                      value="{fields['organization']}"
                      placeholder="Amherst College"></div>
                  </div>
                  <label for="signature">Draft signature</label><textarea
                  id="signature" name="signature" rows="3" maxlength="500"
                  required>{fields['signature']}</textarea>
                  <label for="draft_guidance">How replies should sound</label>
                  <textarea id="draft_guidance" name="draft_guidance" rows="5"
                    maxlength="1200" required>{fields['draft_guidance']}</textarea>
                  <p class="field-note">Describe your tone, what information
                  recruits should send, and the next steps you usually suggest.
                  The assistant still uses only facts available in the email
                  and this approved profile.</p></div>
              </section>
              <section class="panel confirmation">
                <label class="check-row"><input type="checkbox"
                  name="confirm_unsent_drafts" value="yes" required>
                  <span><strong>I approve these labels and generated drafts.</strong>
                  Responses must stay unsent in Gmail until I review and send
                  them myself.</span></label>
                <div class="save-row"><a href="/">Cancel</a>
                  <button type="submit">Save and prepare labels</button></div>
              </section>
            </form>
            <section class="panel danger-zone">
              <div><p class="eyebrow">Disconnect</p><h2>Remove this Gmail account</h2>
                <p>This revokes Google access when available, destroys the local
                credential, stops daily runs, and archives prior settings and history.</p></div>
              <form method="post" action="/disconnect">
                <input type="hidden" name="csrf" value="{self._csrf_value()}">
                <label for="confirmation">Type {_escape(occupant.account)} to confirm</label>
                <div class="disconnect-row"><input id="confirmation"
                  name="confirmation" type="email" required autocomplete="off">
                  <button class="danger" type="submit">Disconnect Gmail</button></div>
              </form>
            </section>
          </main>
        """)

    def _signout_page(self, occupant, error=""):
        error_notice = (
            f'<p class="notice bad">{html.escape(str(error))}</p>' if error else ""
        )
        if occupant is None:
            confirmation = ""
            copy = (
                "No Gmail account is connected. Signing out will only clear "
                "this dashboard session."
            )
            field = ""
            button = "Sign out"
        else:
            confirmation = _escape(occupant.account)
            copy = (
                "This revokes Google access when available, removes the encrypted "
                "Gmail credential, stops future runs, and frees the one-account "
                "slot. Existing Gmail labels and drafts stay in the mailbox."
            )
            field = f"""
              <label for="confirmation">Type {confirmation} to confirm</label>
              <input id="confirmation" name="confirmation" type="email"
                required autocomplete="off">"""
            button = "Sign out &amp; disconnect"
        return self._page("Sign out", f"""
          <main class="login-shell">
            <section class="login-card">
              <div class="mark">ES</div>
              <p class="eyebrow">Account safety</p>
              <h1>Sign out of Email Scanner?</h1>
              <p class="lede">{copy}</p>
              {error_notice}
              <form method="post" action="/logout">
                <input type="hidden" name="csrf" value="{self._csrf_value()}">
                {field}
                <button class="danger" type="submit">{button}</button>
              </form>
              <p class="browser-note"><a href="/">Cancel and return to the
              dashboard</a></p>
            </section>
          </main>
        """)

    @staticmethod
    def _page(title, content):
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · Email Scanner</title>
<style>
:root{{--ink:#102a2a;--muted:#58706e;--line:#d9e5e2;--paper:#f4f8f7;
--card:#fff;--mint:#16a085;--mint-dark:#0d6f61;--blue:#255f85;
--shadow:0 18px 48px rgba(20,63,59,.08)}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
button,input,textarea{{font:inherit}}a{{color:inherit}}.topbar{{height:72px;display:flex;
align-items:center;justify-content:space-between;padding:0 max(24px,calc((100vw - 1180px)/2));
background:rgba(255,255,255,.92);border-bottom:1px solid var(--line)}}
.brand{{display:flex;align-items:center;gap:12px;text-decoration:none;font-weight:750}}
.mark{{display:grid;place-items:center;width:52px;height:52px;border-radius:16px;
background:linear-gradient(145deg,var(--mint),var(--blue));color:white;font-weight:850;
letter-spacing:-.04em;box-shadow:var(--shadow)}}.mark.small{{width:38px;height:38px;border-radius:12px}}
.workspace{{max-width:1180px;margin:auto;padding:44px 24px 72px}}.account-hero{{display:flex;
justify-content:space-between;gap:28px;align-items:flex-start;margin-bottom:30px}}
h1,h2,p{{margin-top:0}}h1{{font-size:clamp(2rem,5vw,3.5rem);line-height:1.05;
letter-spacing:-.045em;margin-bottom:14px}}h2{{font-size:1.3rem;line-height:1.25;
letter-spacing:-.02em;margin-bottom:8px}}.eyebrow{{font-size:.78rem;letter-spacing:.14em;
text-transform:uppercase;font-weight:800;color:var(--mint-dark);margin-bottom:10px}}
.lede{{font-size:1.05rem;color:var(--muted);max-width:650px}}.status{{display:inline-flex;
align-items:center;gap:9px;border:1px solid var(--line);background:white;border-radius:999px;
padding:9px 14px;font-weight:750;white-space:nowrap}}.status i{{width:9px;height:9px;
border-radius:50%;background:#d48a18}}.status.good i{{background:#18a66d;box-shadow:0 0 0 5px #e2f7ee}}
.hero-actions{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}}
.history-run{{display:grid;grid-template-columns:1.2fr .8fr;gap:32px;
align-items:center;margin-bottom:16px}}.history-run form label{{margin:0 0 8px}}
.history-controls{{display:flex;gap:10px;align-items:center}}.history-controls input{{max-width:130px}}
.history-controls button{{white-space:nowrap}}
.overview-grid{{display:grid;grid-template-columns:1.15fr 1fr 1fr;gap:16px;margin-bottom:16px}}
.content-grid{{display:grid;grid-template-columns:1.15fr .85fr;gap:16px;margin-bottom:16px}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:24px;
box-shadow:var(--shadow)}}.panel p:last-child{{margin-bottom:0;color:var(--muted)}}
.section-head{{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}}
.section-actions,.top-actions{{display:flex;align-items:center;gap:10px}}.section-actions .secondary{{font-size:.8rem;padding:7px 10px}}
.metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}.metric{{padding:14px;
background:#f3f8f7;border:1px solid #e4eeeb;border-radius:14px}}.metric span{{display:block;
font-size:.78rem;color:var(--muted);text-transform:capitalize}}.metric strong{{display:block;
font-size:1.75rem;line-height:1.1;margin-top:5px}}.labels ul{{list-style:none;padding:0;margin:0}}
.labels li{{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 0;
border-top:1px solid #edf2f1}}.labels li:first-child{{border-top:0}}.labels li div span{{display:block;
font-size:.8rem;color:var(--muted)}}.tag,.count-badge{{font-size:.75rem;font-weight:750;
background:#e5f5f1;color:var(--mint-dark);border-radius:999px;padding:5px 9px;white-space:nowrap}}
.count-badge{{font-size:.9rem}}.safety{{display:flex;align-items:center;justify-content:space-between;gap:24px}}
.secondary,button{{border:0;border-radius:12px;padding:11px 16px;font-weight:750;cursor:pointer}}
.secondary{{background:var(--ink);color:white;text-decoration:none;white-space:nowrap}}button{{background:var(--mint-dark);color:white}}
button:disabled{{opacity:.45;cursor:not-allowed}}
.ghost{{background:transparent;color:var(--muted);border:1px solid var(--line)}}.ghost-link{{color:var(--muted);text-decoration:none;font-weight:700}}.empty{{color:var(--muted)}}
.login-shell{{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 20% 10%,#dff7f0,transparent 38%),var(--paper)}}
.login-card{{width:min(460px,100%);padding:42px;background:white;border:1px solid var(--line);
border-radius:24px;box-shadow:var(--shadow)}}.login-card .mark{{margin-bottom:26px}}
.login-card h1{{font-size:2.35rem}}label{{display:block;font-weight:750;margin:24px 0 8px}}
input:not([type=hidden]):not([type=checkbox]),textarea{{width:100%;padding:13px 14px;border:1px solid #b9cdca;border-radius:12px;
outline:none;background:white;color:var(--ink)}}textarea{{resize:vertical}}input:focus,textarea:focus{{border-color:var(--mint);box-shadow:0 0 0 4px #dff7f0}}
.login-card button{{width:100%;margin-top:14px}}.google-button{{display:flex;align-items:center;width:100%;
justify-content:center;gap:11px;background:#fff;color:#223;border:1px solid #aebfbd;
border-radius:12px;padding:12px 16px;margin-top:14px;text-decoration:none;font-weight:750;
box-shadow:0 4px 14px rgba(20,63,59,.08)}}.google-button span{{display:grid;place-items:center;
width:24px;height:24px;border-radius:50%;background:#fff;color:#1769e0;font-weight:850}}
.browser-note{{margin:16px 0 0;color:var(--muted);font-size:.88rem;text-align:center}}
.notice{{padding:11px 13px;border-radius:10px}}.notice.bad{{background:#fff0ed;color:#9b3024}}
.notice.good{{background:#e2f7ee;color:#116645}}.notice.progress{{background:#eaf3f8;color:#24556f}}
.failure-alert{{display:flex;align-items:center;justify-content:space-between;gap:24px;
padding:20px 22px;margin-bottom:22px;background:#fff0ed;border:1px solid #efc1b8;
border-radius:18px;color:#7d281f}}.failure-alert .eyebrow{{color:#9b3024}}
.failure-alert h2,.failure-alert p{{margin-bottom:4px}}.run-progress{{margin-bottom:16px}}
.run-progress .section-head{{align-items:center;margin-bottom:12px}}.run-progress progress{{width:100%;
height:14px;accent-color:var(--mint-dark)}}.run-progress>p{{font-size:.85rem;margin-top:8px}}
.settings-shell{{max-width:980px}}.account-hero.compact h1{{font-size:clamp(2rem,4vw,3rem)}}
.settings-form{{display:grid;gap:16px}}.form-section{{display:grid;grid-template-columns:.75fr 1.25fr;gap:38px}}
.form-copy p{{color:var(--muted)}}.form-section label{{margin:0 0 8px}}.form-section label:not(:first-child){{margin-top:18px}}
.field-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}.field-note{{font-size:.8rem;color:var(--muted);margin:7px 0 0}}
.confirmation{{display:grid;gap:22px}}.check-row{{display:flex;gap:13px;align-items:flex-start;margin:0}}
.check-row input{{margin-top:5px;accent-color:var(--mint-dark)}}.check-row span{{color:var(--muted)}}.check-row strong{{color:var(--ink)}}
.save-row{{display:flex;align-items:center;justify-content:flex-end;gap:18px}}.save-row a{{color:var(--muted)}}
.danger-zone{{margin-top:26px;border-color:#f0cbc5;box-shadow:none;display:grid;grid-template-columns:.8fr 1.2fr;gap:38px}}
.danger-zone p{{color:var(--muted)}}.danger-zone label{{margin:0 0 8px}}.disconnect-row{{display:flex;gap:10px;align-items:center}}
.danger{{background:#a33b2e;white-space:nowrap}}
.coach-card{{display:flex;align-items:center;justify-content:space-between;gap:24px;
margin-bottom:16px}}.coach-card p{{margin-bottom:0}}.review-queue{{margin-bottom:16px}}
.draft-list{{display:grid;gap:12px}}.draft-card{{padding:18px;border:1px solid #dce8e5;
border-radius:16px;background:#f9fbfb}}.draft-card-head{{display:flex;align-items:center;
justify-content:space-between;gap:16px}}.draft-card-head>div{{display:flex;align-items:center;
gap:9px;flex-wrap:wrap}}.confidence{{font-size:.8rem;color:var(--muted)}}
.recruit-fields{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;
margin-top:16px}}.recruit-fields span{{padding:10px 11px;background:white;border:1px solid #e2ecea;
border-radius:12px;overflow-wrap:anywhere}}.recruit-fields small{{display:block;color:var(--muted);
font-size:.72rem;margin-bottom:3px}}.verify-note{{font-size:.78rem;margin:12px 0 0!important}}
.coach-fields label{{margin-top:18px!important}}
@media(max-width:850px){{.overview-grid,.content-grid{{grid-template-columns:1fr}}.account-hero,
.safety,.coach-card,.failure-alert{{flex-direction:column;align-items:flex-start}}.metrics{{grid-template-columns:repeat(2,1fr)}}.form-section,.danger-zone,.history-run{{grid-template-columns:1fr;gap:18px}}.recruit-fields{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:480px){{.workspace{{padding:30px 16px 56px}}.topbar{{padding:0 16px}}
.panel{{padding:20px}}.metrics,.field-grid,.recruit-fields{{grid-template-columns:1fr}}h1{{font-size:2rem}}.brand>span:last-child,.ghost-link{{display:none}}.section-actions,.draft-card-head{{align-items:flex-start;flex-direction:column}}.disconnect-row{{align-items:stretch;flex-direction:column}}}}
</style></head><body>{content}</body></html>"""


def build_application(env=None):
    import os
    from hosted_control import HostedControl, HostedControlConfig

    values = env if env is not None else os.environ
    config = HostedConfig.from_environment(values, verify_root=True)
    control_config = HostedControlConfig.from_environment(
        values, config.state_root
    )
    return HostedDashboardApp(config, control=HostedControl(control_config))
