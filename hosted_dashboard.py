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
import logging
import re
from pathlib import Path
from urllib.parse import parse_qs, quote

import connection
import connection_schedule
import hosted_run_request
import hosted_settings
from hosted_status import HostedConfig, status_document
from rollback_journal import latest_summary


logger = logging.getLogger(__name__)

SESSION_COOKIE = "email_scanner_session"
# Without an explicit Max-Age this was a browser session cookie, cleared the
# moment the browser was fully quit rather than just the tab closed - the
# owner had to click "Continue with Google" again on every fresh browser
# launch, even though the underlying Gmail grant (production OAuth, not
# testing mode) was still good for months. 30 days trades that friction
# against a real cost: this cookie is one static value shared by every
# session rather than per-login, so there is no way to sign out one device
# without signing out all of them, and quitting the browser was the only
# thing that ever cleared a stale one. A device that stays signed in now
# stays signed in for the full window instead of clearing itself on its own.
SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
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

# The envelope mark, as plain SVG source. The one source of truth for both
# the in-page <link rel="icon"> (built from it below) and the direct
# /favicon.ico route: browsers commonly probe /favicon.ico on their own,
# separately from the <link> tag, and cache a failed answer there stubbornly,
# so the icon has to be reachable at that literal path too, not just embedded
# in the page.
#
# FILLED shapes, not thin strokes. The in-page .mark glyph (in the CSS below)
# uses a thin-stroke outline and reads fine there because it renders at
# 30-56px. A favicon renders at 16-32px through each browser's own tab-icon
# pipeline, which is commonly cruder than ordinary image rendering and can
# lose a ~2px stroke entirely - a real report showed exactly a plain blue
# square with the envelope lines gone. A solid fill has no thin line to
# lose, so it is the robust choice for this specific use regardless of the
# exact cause.
FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
    "<rect width='24' height='24' rx='7.2' fill='#0071e3'/>"
    "<rect x='3' y='6' width='18' height='12.5' rx='2' fill='#fff'/>"
    "<path d='M3 6.8 12 13.6 21 6.8 21 6 3 6Z' fill='#0071e3'/>"
    "</svg>"
)
FAVICON_HREF = "data:image/svg+xml," + quote(FAVICON_SVG)

HTML_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
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
    "history_backfill_invalid": "The saved background scan needs attention.",
    "account_setup_incomplete": "Finish the coach profile and label settings.",
    "label_setup_failed": "Gmail labels could not be prepared. Save settings again.",
    "label_setup_invalid": "The saved label plan needs to be refreshed.",
    "rollback_incomplete": "Some previous-run changes still need to be undone.",
    "rollback_failed": "The previous run could not be undone safely.",
}


def _render_run_progress(details):
    if details.get("outcome") != "running":
        return ""
    current = details.get("current", 0)
    total = details.get("total", 0)
    percent = round((current / total) * 100) if total else 0
    stage = _escape(details.get("stage"), "Working")
    amount = f"{current} of {total}" if total else "Preparing"
    estimate = ""
    started = _timestamp(details.get("started_at"))
    if started and current > 0 and total > current:
        elapsed = max(1, (dt.datetime.now(dt.timezone.utc) - started).total_seconds())
        remaining_minutes = max(1, round((elapsed / current) * (total - current) / 60))
        estimate = f" · about {remaining_minutes} min remaining"
    return f"""
      <section class="panel run-progress" aria-live="polite">
        <div class="section-head"><div><p class="eyebrow">Live run</p>
          <h2>{stage}</h2></div><strong>{html.escape(amount)}</strong></div>
        <progress max="{max(1, total)}" value="{min(current, max(1, total))}">{percent}%</progress>
        <p>{percent}% complete{estimate} · updates every {RUN_REFRESH_SECONDS} seconds.</p>
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
    def __init__(self, config, clock=None, control=None, run_requester=None,
                 undo_requester=None):
        self.config = config
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.control = control
        self.run_requester = run_requester or hosted_run_request.request_run
        self.undo_requester = undo_requester or hosted_run_request.request_undo

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
        maximum = (
            "; Max-Age=0" if clear else f"; Max-Age={SESSION_MAX_AGE_SECONDS}"
        )
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

        # Browsers commonly fetch /favicon.ico on their own, independent of
        # the <link rel="icon"> tag, and cache a failed answer there
        # stubbornly - so this has to be a real, unauthenticated route rather
        # than falling through to the session gate below and 303-ing to
        # /login, which is what happened before this route existed.
        if path == "/favicon.ico" and method in {"GET", "HEAD"}:
            payload = FAVICON_SVG.encode("utf-8")
            start_response("200 OK", [
                ("Content-Type", "image/svg+xml"),
                ("Cache-Control", "public, max-age=604800, immutable"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Length", str(len(payload))),
            ])
            return [b"" if head else payload]

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

        if path == "/undo" and method in {"GET", "HEAD"}:
            try:
                occupant = connection.current(self.config.state_root)
                summary = latest_summary(occupant.directory) if occupant else None
            except connection.ConnectionConfigError:
                summary = None
            if summary is None:
                return self._redirect(start_response, "/")
            return self._respond(
                start_response, "200 OK", self._undo_page(summary), head=head
            )

        if path == "/undo" and method == "POST":
            form = self._form(environ)
            if form is None or not self._csrf_ok(form):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused.</h1>"),
                )
            try:
                requested_epoch = self.undo_requester(
                    self.config.state_root,
                    group_id=str(form.get("group_id", "")),
                    confirmation=str(form.get("confirmation", "")),
                    now=self.clock(),
                )
            except hosted_run_request.RunAlreadyActive:
                return self._redirect(start_response, "/?undo=busy")
            except (hosted_run_request.RunRequestError,
                    connection.ConnectionError,
                    connection.ConnectionConfigError, OSError):
                return self._redirect(start_response, "/?undo=failed")
            return self._redirect(
                start_response,
                f"/?run=requested&undo=requested&after={requested_epoch}",
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
                from hosted_control import HostedControlError

                try:
                    self.control.disconnect(form.get("confirmation", ""))
                except HostedControlError as exc:
                    # This message is documented as user-safe (never token or
                    # OAuth detail) and already says exactly what went wrong -
                    # a real mismatch, or no account connected - so it is
                    # shown as-is rather than replaced with a guess.
                    try:
                        occupant = connection.current(self.config.state_root)
                    except connection.ConnectionConfigError:
                        occupant = None
                    if occupant is not None:
                        return self._respond(
                            start_response, "400 Bad Request",
                            self._signout_page(occupant, str(exc)),
                        )
                except Exception:  # noqa: BLE001 - keep provider detail private
                    # Anything else - a lock, an archive write, a revocation
                    # call - is not a confirmation mismatch, and telling the
                    # owner to retype an address they already typed correctly
                    # only hides the real fault. Logged here because
                    # disconnect() itself never does, and this was previously
                    # the only place such a failure could be seen at all.
                    logger.exception("Gmail disconnect failed")
                    try:
                        occupant = connection.current(self.config.state_root)
                    except connection.ConnectionConfigError:
                        occupant = None
                    if occupant is not None:
                        return self._respond(
                            start_response, "400 Bad Request",
                            self._signout_page(
                                occupant,
                                "Sign out failed unexpectedly. Try again in a "
                                "moment.",
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
            undo_state = (query.get("undo") or [""])[-1]
            if undo_state == "requested" and run_state == "requested":
                run_notice = (
                    '<p class="notice progress"><strong>Undo queued.</strong> '
                    'Drafts and labels will be rolled back in the background.</p>'
                )
            elif undo_state == "busy":
                run_notice = (
                    '<p class="notice bad">A mailbox operation is already '
                    'running. Wait for it to finish before undoing.</p>'
                )
            elif undo_state == "failed":
                run_notice = (
                    '<p class="notice bad">The undo request was refused. '
                    'Nothing was changed.</p>'
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

            from hosted_control import HostedControlError

            try:
                self.control.disconnect(form.get("confirmation", ""))
            except HostedControlError as exc:
                # User-safe by construction: a real mismatch, or no account
                # connected. Shown as-is rather than replaced with a guess.
                try:
                    occupant = connection.current(self.config.state_root)
                except connection.ConnectionConfigError:
                    occupant = None
                if occupant is None:
                    return self._redirect(start_response, "/")
                return self._respond(
                    start_response, "400 Bad Request",
                    self._settings_page(occupant, error=str(exc)),
                )
            except Exception:  # noqa: BLE001 - KMS/revocation detail stays private
                # Not a confirmation mismatch - a lock, an archive write, a
                # revocation call. Telling the owner to retype an address
                # they already typed correctly only hides the real fault.
                logger.exception("Gmail disconnect failed")
                try:
                    occupant = connection.current(self.config.state_root)
                except connection.ConnectionConfigError:
                    occupant = None
                if occupant is None:
                    return self._redirect(start_response, "/")
                return self._respond(
                    start_response, "400 Bad Request",
                    self._settings_page(
                        occupant,
                        error="disconnect failed unexpectedly; try again in "
                              "a moment",
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
            rollback_summary = None
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
            rollback_summary = latest_summary(occupant.directory)

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
              <h2>Start background backfill</h2>
              <p>Scan previous emails in the background. Choose how many of
              the newest eligible messages to check.
              Every message with a usable reply address ends with one unsent
              draft. Existing drafts are kept, and deleted program drafts are
              rebuilt instead of being silently skipped.
              Large backfills run in resumable groups while new-mail scans keep
              priority between groups. You can close this page and return later.</p></div>
            <form method="post" action="/run-history">
              <input type="hidden" name="csrf" value="{self._csrf_value()}">
              <label for="message_count">Previous messages</label>
              <div class="history-controls"><input id="message_count"
                name="message_count" type="number" min="1"
                max="{hosted_run_request.MAX_HISTORY_MESSAGES}"
                value="{min(50, hosted_run_request.MAX_HISTORY_MESSAGES)}"
                required><button type="submit">Start backfill</button></div>
            </form>
          </section>""" if occupant is not None else ""
        rollback_card = f"""
          <section class="panel undo-run">
            <div><p class="eyebrow">Previous run</p>
              <h2>Undo drafts and labels</h2>
              <p>Undo {_escape(rollback_summary.get('drafts'))} created drafts
              and {_escape(rollback_summary.get('labels'))} label changes across
              {_escape(rollback_summary.get('messages'))} emails. You will review
              the impact and confirm before anything changes. There is no item
              limit.</p></div>
            <a class="secondary danger-link" href="/undo">Review undo</a>
          </section>""" if rollback_summary is not None else ""

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
            {rollback_card}

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

    def _undo_page(self, summary):
        return self._page("Undo previous run", f"""
          <header class="topbar">
            <a class="brand" href="/"><span class="mark small">ES</span>
              <span>Email Scanner</span></a>
            <a class="ghost-link" href="/">Cancel</a>
          </header>
          <main class="workspace settings-shell">
            <section class="panel danger-zone undo-confirm">
              <div><p class="eyebrow">Confirm rollback</p>
                <h1>Undo the previous run?</h1>
                <p>This will remove {_escape(summary.get('labels'))} labels added
                by that run and move {_escape(summary.get('drafts'))} drafts to
                Gmail Trash. If you edited one of those drafts, your edits will
                move to Trash with it. The whole run is included, regardless of
                size. No email will be sent.</p></div>
              <form method="post" action="/undo">
                <input type="hidden" name="csrf" value="{self._csrf_value()}">
                <input type="hidden" name="group_id"
                  value="{_escape(summary.get('group_id'), '')}">
                <label for="confirmation">Type UNDO to continue</label>
                <input id="confirmation" name="confirmation"
                  autocomplete="off" required>
                <button class="danger" type="submit">Undo previous run</button>
              </form>
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
<link rel="icon" type="image/svg+xml" href="{FAVICON_HREF}">
<style>
/* Email Scanner — Apple-style UI refresh
   Drop-in replacement for the <style> block in hosted_dashboard.py :: _page().
   Every existing class name is preserved; no markup or behavior changes needed.
   The "ES" lettermark is replaced by a CSS-drawn envelope glyph (.mark). */

:root{{
  --bg:#f5f5f7; --paper:#f5f5f7; --card:#fff; --surface2:#fbfbfd; --fill:#f2f2f7;
  --ink:#1d1d1f; --muted:#6e6e73; --ink3:#8e8e93;
  --line:rgba(0,0,0,.09); --line2:rgba(0,0,0,.05);
  --blue:#0071e3; --blue-press:#0058b8; --blue-soft:rgba(0,113,227,.10);
  --mint:#0071e3; --mint-dark:#0071e3;           /* legacy aliases → system blue */
  --green:#2eb350; --green-soft:rgba(52,199,89,.14);
  --red:#d70015; --red-soft:rgba(255,59,48,.10); --amber:#b25000;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 10px 30px rgba(0,0,0,.06);
  --shadow-sm:0 1px 2px rgba(0,0,0,.06);
  --bar:rgba(250,250,252,.72);
  --ease-spring:cubic-bezier(.34,1.56,.64,1);
}}
@media (prefers-color-scheme:dark){{
  :root{{
    --bg:#000; --paper:#000; --card:#1c1c1e; --surface2:#242426; --fill:#2c2c2e;
    --ink:#f5f5f7; --muted:#a1a1a6; --ink3:#8e8e93;
    --line:rgba(255,255,255,.13); --line2:rgba(255,255,255,.07);
    --blue:#0a84ff; --blue-press:#409cff; --blue-soft:rgba(10,132,255,.18);
    --mint:#0a84ff; --mint-dark:#0a84ff;
    --green:#30d158; --green-soft:rgba(48,209,88,.18);
    --red:#ff453a; --red-soft:rgba(255,69,58,.16); --amber:#ff9f0a;
    --shadow:0 1px 2px rgba(0,0,0,.5),0 12px 36px rgba(0,0,0,.55);
    --shadow-sm:0 1px 2px rgba(0,0,0,.5);
    --bar:rgba(28,28,30,.72);
  }}
}}

*{{box-sizing:border-box}}
html{{-webkit-text-size-adjust:100%}}
body{{
  margin:0; background:var(--paper); color:var(--ink);
  font:16px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue",system-ui,sans-serif;
  letter-spacing:-.011em; -webkit-font-smoothing:antialiased;
}}
button,input,textarea,select{{font:inherit}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{color:var(--blue-press)}}
:focus-visible{{outline:3px solid var(--blue-soft);outline-offset:2px;border-radius:10px}}
::selection{{background:var(--blue-soft)}}

/* ---------- header ---------- */
.topbar{{
  height:60px;display:flex;align-items:center;justify-content:space-between;gap:20px;
  padding:0 max(24px,calc((100vw - 1180px)/2));
  background:var(--bar);backdrop-filter:saturate(180%) blur(20px);
  -webkit-backdrop-filter:saturate(180%) blur(20px);
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:50;
}}
.brand{{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;color:var(--ink)}}
.brand:hover{{color:var(--ink)}}
.top-actions,.section-actions{{display:flex;align-items:center;gap:6px;flex-wrap:wrap}}

/* envelope lettermark — text is hidden, glyph is a background SVG */
.mark{{
  display:grid;place-items:center;width:30px;height:30px;border-radius:9px;
  background:var(--blue);color:transparent;font-size:0;flex:none;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23fff' stroke-width='1.9' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='2.75' y='5.25' width='18.5' height='13.5' rx='2.75'/%3E%3Cpath d='M4 7.5 12 13.25 20 7.5'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:center;background-size:56%;
}}
.mark.small{{width:30px;height:30px;border-radius:9px}}
.login-card .mark{{width:56px;height:56px;border-radius:16px;margin-bottom:26px;box-shadow:0 8px 20px var(--blue-soft)}}

/* ---------- layout ---------- */
.workspace{{max-width:1180px;margin:auto;padding:44px 24px 80px}}
.settings-shell{{max-width:980px}}
h1,h2,p{{margin-top:0}}
h1{{font-size:clamp(2rem,4.4vw,3.25rem);line-height:1.05;letter-spacing:-.035em;font-weight:700;margin-bottom:12px}}
h2{{font-size:1.31rem;line-height:1.25;letter-spacing:-.02em;font-weight:650;margin-bottom:8px}}
.eyebrow{{font-size:.81rem;font-weight:600;letter-spacing:0;text-transform:none;color:var(--muted);margin-bottom:8px}}
.lede{{font-size:1.06rem;color:var(--muted);max-width:650px;text-wrap:pretty}}
.empty{{color:var(--muted)}}

.account-hero{{display:flex;justify-content:space-between;gap:28px;align-items:flex-start;flex-wrap:wrap;margin-bottom:36px}}
.account-hero>div:first-child{{flex:1 1 420px;min-width:0}}
.account-hero.compact h1{{font-size:clamp(1.9rem,3.6vw,2.75rem)}}
.hero-actions{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}}

.overview-grid,.content-grid{{display:grid;gap:16px;margin-bottom:16px}}
.overview-grid{{grid-template-columns:repeat(auto-fit,minmax(270px,1fr))}}
.content-grid{{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}}

/* ---------- panels ---------- */
.panel{{
  background:var(--card);border:1px solid var(--line);border-radius:20px;padding:26px;
  box-shadow:var(--shadow);transition:transform .25s cubic-bezier(.34,1.3,.64,1),box-shadow .25s ease;
}}
.overview-grid .panel:hover{{transform:translateY(-2px)}}
.panel p:last-child{{margin-bottom:0;color:var(--muted)}}
.section-head{{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px}}
.section-head>div:first-child{{flex:1 1 auto;min-width:0}}
.section-actions .secondary{{font-size:.875rem;padding:9px 14px}}

/* ---------- metrics ---------- */
.metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
.metric{{padding:16px;background:var(--fill);border:0;border-radius:14px}}
.metric span{{display:block;font-size:.81rem;color:var(--muted);text-transform:capitalize}}
.metric strong{{display:block;font-size:1.87rem;line-height:1.1;margin-top:4px;font-weight:650;letter-spacing:-.03em;font-variant-numeric:tabular-nums}}

/* ---------- labels list ---------- */
.labels ul{{list-style:none;padding:0;margin:0}}
.labels li{{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0;border-top:1px solid var(--line2)}}
.labels li:first-child{{border-top:0}}
.labels li div span{{display:block;font-size:.81rem;color:var(--muted)}}
.tag,.count-badge{{font-size:.75rem;font-weight:600;background:var(--fill);color:var(--muted);border-radius:980px;padding:5px 10px;white-space:nowrap}}
.count-badge{{font-size:.83rem;background:var(--blue-soft);color:var(--blue)}}

/* ---------- status pill ---------- */
.status{{
  display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);
  background:var(--card);border-radius:980px;padding:9px 15px;font-size:.875rem;
  font-weight:600;white-space:nowrap;box-shadow:var(--shadow-sm);
}}
.status i{{width:8px;height:8px;border-radius:50%;background:var(--amber)}}
.status.good i{{background:var(--green);box-shadow:0 0 0 4px var(--green-soft)}}

/* ---------- buttons: springy press feedback ---------- */
.secondary,button{{
  border:0;border-radius:980px;padding:11px 18px;font-size:.94rem;font-weight:600;cursor:pointer;
  transition:transform .18s var(--ease-spring),background .2s ease,filter .2s ease;
}}
button{{background:var(--blue);color:#fff}}
button:hover{{background:var(--blue-press)}}
.secondary{{background:var(--fill);color:var(--ink);text-decoration:none;white-space:nowrap;display:inline-block}}
.secondary:hover{{color:var(--ink);filter:brightness(.96)}}
.secondary:active,button:active{{transform:scale(.95)}}
button:disabled{{opacity:.42;cursor:not-allowed;transform:none}}
.ghost{{background:var(--card);color:var(--ink);border:1px solid var(--line)}}
.ghost:hover{{background:var(--fill)}}
.ghost-link{{color:var(--muted);font-weight:500;padding:7px 12px;border-radius:980px}}
.ghost-link:hover{{background:var(--fill);color:var(--ink)}}
.danger,.danger-link{{background:var(--red);color:#fff;white-space:nowrap}}
.danger:hover,.danger-link:hover{{background:var(--red);color:#fff;filter:brightness(.92)}}
.section-actions .danger-link,.undo-run .danger-link{{background:var(--red-soft);color:var(--red)}}
.section-actions .danger-link:hover,.undo-run .danger-link:hover{{color:var(--red);filter:brightness(.97)}}

/* ---------- forms ---------- */
label{{display:block;font-size:.875rem;font-weight:600;margin:24px 0 8px}}
input:not([type=hidden]):not([type=checkbox]),textarea{{
  width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:12px;outline:none;
  background:var(--fill);color:var(--ink);
  transition:box-shadow .2s ease,border-color .2s ease,background .2s ease;
}}
textarea{{border-radius:14px;resize:vertical;line-height:1.55}}
input:focus,textarea:focus{{border-color:var(--blue);box-shadow:0 0 0 4px var(--blue-soft);background:var(--card)}}
.field-note{{font-size:.81rem;color:var(--ink3);margin:7px 0 0}}
.field-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px}}
.settings-form{{display:grid;gap:16px}}
.form-section{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:36px}}
.form-copy p{{color:var(--muted)}}
.form-copy .eyebrow{{color:var(--blue)}}
.form-section label{{margin:0 0 8px}}
.form-section label:not(:first-child){{margin-top:18px}}
.coach-fields label{{margin-top:18px!important}}
.confirmation{{display:grid;gap:22px}}
.check-row{{display:flex;gap:14px;align-items:flex-start;margin:0;cursor:pointer}}
.check-row input{{width:20px;height:20px;margin-top:2px;accent-color:var(--blue);cursor:pointer;flex:none}}
.check-row span{{color:var(--muted)}}
.check-row strong{{color:var(--ink);font-weight:600}}
.save-row{{display:flex;align-items:center;justify-content:flex-end;gap:18px}}
.save-row a{{color:var(--muted);font-weight:500}}
.save-row a:hover{{color:var(--ink)}}

/* ---------- history / undo / coach / safety rows ---------- */
.history-run{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:32px;align-items:center;margin-bottom:16px}}
.history-run form label{{margin:0 0 8px}}
.history-controls{{display:flex;gap:10px;align-items:center}}
.history-controls input{{max-width:130px}}
.history-controls button{{white-space:nowrap}}
.undo-run,.coach-card,.safety{{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;margin-bottom:16px}}
.undo-run>div:first-child,.coach-card>div:first-child{{flex:1 1 380px;min-width:0}}
.coach-card p{{margin-bottom:0}}
.undo-confirm h1{{font-size:2.2rem}}

/* ---------- danger zone ---------- */
.danger-zone{{
  margin-top:26px;border-color:var(--red-soft);box-shadow:none;
  display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:36px;
}}
.danger-zone .eyebrow{{color:var(--red)}}
.danger-zone p{{color:var(--muted)}}
.danger-zone label{{margin:0 0 8px}}
.disconnect-row{{display:flex;gap:10px;align-items:center}}
.danger-zone input:focus{{border-color:var(--red);box-shadow:0 0 0 4px var(--red-soft)}}

/* ---------- notices ---------- */
.notice{{padding:13px 16px;border-radius:14px;font-weight:500;margin-bottom:16px}}
.notice.bad{{background:var(--red-soft);color:var(--red)}}
.notice.good{{background:var(--green-soft);color:var(--green)}}
.notice.progress{{background:var(--blue-soft);color:var(--blue)}}
.failure-alert{{
  display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;
  padding:20px 22px;margin-bottom:22px;background:var(--red-soft);
  border:1px solid var(--red-soft);border-radius:18px;color:var(--ink);
}}
.failure-alert>div:first-child{{flex:1 1 380px;min-width:0}}
.failure-alert .eyebrow{{color:var(--red);font-weight:700}}
.failure-alert h2{{margin-bottom:4px;color:var(--ink)}}
.failure-alert p{{margin-bottom:0;color:var(--muted)}}

/* ---------- run progress ---------- */
.run-progress{{margin-bottom:16px}}
.run-progress .section-head{{align-items:center;margin-bottom:14px}}
.run-progress progress{{
  width:100%;height:10px;border:0;border-radius:980px;overflow:hidden;
  background:var(--fill);accent-color:var(--blue);appearance:none;-webkit-appearance:none;
}}
.run-progress progress::-webkit-progress-bar{{background:var(--fill);border-radius:980px}}
.run-progress progress::-webkit-progress-value{{background:var(--blue);border-radius:980px;transition:width .6s cubic-bezier(.4,0,.2,1)}}
.run-progress progress::-moz-progress-bar{{background:var(--blue);border-radius:980px}}
.run-progress>p{{font-size:.875rem;margin-top:10px}}

/* ---------- review queue ---------- */
.review-queue{{margin-bottom:16px}}
.draft-list{{display:grid;gap:12px}}
.draft-card{{padding:20px;border:1px solid var(--line);border-radius:16px;background:var(--surface2)}}
.draft-card-head{{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}}
.draft-card-head>div{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.draft-card .tag{{background:var(--blue-soft);color:var(--blue)}}
.confidence{{font-size:.83rem;color:var(--muted)}}
.recruit-fields{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:16px}}
.recruit-fields span{{padding:11px 12px;background:var(--card);border:1px solid var(--line);border-radius:12px;font-size:.875rem;overflow-wrap:anywhere}}
.recruit-fields small{{display:block;color:var(--muted);font-size:.75rem;margin-bottom:3px}}
.verify-note{{font-size:.81rem;color:var(--ink3);margin:12px 0 0!important}}

/* ---------- login / signout cards ---------- */
.login-shell{{
  min-height:100vh;display:grid;place-items:center;padding:24px;
  background:radial-gradient(90% 90% at 20% 0%,var(--blue-soft),transparent 60%),var(--paper);
}}
.login-card{{
  width:min(460px,100%);padding:40px 36px;background:var(--card);
  border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow);
}}
.login-card h1{{font-size:2.15rem}}
.login-card button{{width:100%;margin-top:16px;border-radius:14px;padding:13px 20px;font-size:1rem}}
.google-button{{
  display:flex;align-items:center;justify-content:center;gap:10px;width:100%;
  background:var(--blue);color:#fff;border:0;border-radius:14px;padding:13px 18px;
  margin-top:16px;font-size:1rem;font-weight:600;
  transition:transform .18s var(--ease-spring),background .2s ease;
}}
.google-button:hover{{background:var(--blue-press);color:#fff}}
.google-button:active{{transform:scale(.97)}}
.google-button span{{display:grid;place-items:center;width:22px;height:22px;border-radius:50%;background:#fff;color:#1769e0;font-size:.81rem;font-weight:800}}
.browser-note{{margin:18px 0 0;color:var(--ink3);font-size:.83rem;line-height:1.45;text-align:center}}

/* ---------- responsive ---------- */
@media (max-width:850px){{
  .account-hero,.safety,.coach-card,.undo-run,.failure-alert{{flex-direction:column;align-items:flex-start}}
  .hero-actions{{justify-content:flex-start}}
  .metrics{{grid-template-columns:repeat(2,1fr)}}
}}
@media (max-width:480px){{
  .workspace{{padding:30px 16px 60px}}
  .topbar{{padding:0 16px}}
  .panel{{padding:20px}}
  .metrics,.recruit-fields{{grid-template-columns:1fr}}
  h1{{font-size:2rem}}
  .brand>span:last-child{{display:none}}
  .draft-card-head{{align-items:flex-start;flex-direction:column}}
  .disconnect-row{{align-items:stretch;flex-direction:column}}
}}
@media (prefers-reduced-motion:reduce){{
  *{{transition:none!important;animation:none!important}}
}}
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
