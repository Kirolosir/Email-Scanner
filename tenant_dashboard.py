"""WSGI account boundary for the PostgreSQL-backed hosted dashboard."""
from __future__ import annotations

import datetime as dt
import hmac
import html
import json
import math
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode

from hosted_control import HostedControlError
from hosted_dashboard import HTML_HEADERS, SESSION_COOKIE, SESSION_MAX_AGE_SECONDS
from rollback_journal import latest_summary
from tenant_store import TenantAccessDenied, csrf_value


MAX_FORM_BYTES = 8192
SUMMARY_KEYS = ("scanned", "labeled", "drafted", "skipped", "failures")


def _read_json(path):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, dict) else {}


def _job_counts(directory, job_id):
    counts = {key: 0 for key in SUMMARY_KEYS}
    if job_id is None:
        return counts
    try:
        paths = sorted((Path(directory) / "review").glob(f"job-{job_id}-*.json"))
    except OSError:
        return counts
    for path in paths:
        raw = _read_json(path).get("counts")
        if not isinstance(raw, dict):
            continue
        for key in counts:
            value = raw.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                counts[key] += value
    return counts


def _display_time(value, fallback="Not scheduled"):
    if not isinstance(value, dt.datetime):
        return fallback
    return value.astimezone(dt.timezone.utc).strftime("%b %-d, %Y · %-I:%M %p UTC")


def _eta(mailbox, now):
    if (mailbox.last_job_status != "running" or not mailbox.last_job_started_at
            or not mailbox.requested_count or mailbox.processed_count <= 0):
        return "Calculating after the first group"
    elapsed = max(1, (now - mailbox.last_job_started_at).total_seconds())
    remaining = max(0, mailbox.requested_count - mailbox.processed_count)
    seconds = int(elapsed / mailbox.processed_count * remaining)
    if seconds < 60:
        return "Less than a minute"
    if seconds < 3600:
        return f"About {math.ceil(seconds / 60)} minutes"
    return f"About {math.ceil(seconds / 3600)} hours"


def _cookies(environ):
    found = {}
    for part in str(environ.get("HTTP_COOKIE", "")).split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key:
            found[key] = value
    return found


class TenantDashboardApp:
    def __init__(self, config, store, control, *, clock=None):
        self.config = config
        self.store = store
        self.control = control
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def _identity(self, environ):
        token = _cookies(environ).get(SESSION_COOKIE, "")
        if not token:
            return None
        try:
            return self.store.authenticate_session(token, now=self.clock())
        except TenantAccessDenied:
            return None

    def _cookie(self, token="", *, clear=False):
        secure = "; Secure" if self.config.require_forwarded_https else ""
        age = 0 if clear else SESSION_MAX_AGE_SECONDS
        value = "" if clear else token
        return (
            f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax"
            f"{secure}; Max-Age={age}"
        )

    @staticmethod
    def _redirect(start_response, location, headers=()):
        start_response("303 See Other", list(HTML_HEADERS) + list(headers) + [
            ("Location", location), ("Content-Length", "0"),
        ])
        return [b""]

    @staticmethod
    def _respond(start_response, status, body, head=False):
        payload = body.encode("utf-8")
        start_response(status, list(HTML_HEADERS) + [
            ("Content-Length", str(len(payload))),
        ])
        return [b"" if head else payload]

    @staticmethod
    def _form(environ):
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            return None
        if not 0 <= length <= MAX_FORM_BYTES:
            return None
        raw = environ.get("wsgi.input").read(length).decode("utf-8")
        values = parse_qs(raw, keep_blank_values=True)
        return {key: entries[-1] for key, entries in values.items() if entries}

    @staticmethod
    def _page(title, content, *, refresh=False):
        refresh_tag = '<meta http-equiv="refresh" content="4">' if refresh else ""
        return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width">
{refresh_tag}
<title>{html.escape(title)} · Email Scanner</title>
<style>
*{{box-sizing:border-box}}:root{{--blue:#0672e5;--ink:#14213d;--muted:#667085;
--line:#e4e9f1;--surface:#fff;--bg:#f5f7fb;--green:#087a55;--amber:#a35b00;
--red:#c0362c}}body{{font:15px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
margin:0;background:var(--bg);color:var(--ink)}}main{{max-width:1120px;margin:0 auto;padding:38px 22px 72px}}
.topbar{{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}}
.brand{{display:flex;align-items:center;gap:12px}}.mark{{width:42px;height:42px;border-radius:13px;
background:var(--blue);color:#fff;display:grid;place-items:center;font-size:22px}}h1,h2,h3,p{{margin-top:0}}
h1{{font-size:1.8rem;margin-bottom:3px}}h2{{font-size:1.25rem}}h3{{font-size:.96rem;margin-bottom:5px}}
.panel{{background:var(--surface);padding:24px;border:1px solid var(--line);border-radius:20px;
box-shadow:0 8px 28px rgba(20,33,61,.045);margin:16px 0}}.mailbox-head{{display:flex;
align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}}.row{{display:flex;gap:10px;
align-items:center;flex-wrap:wrap}}.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}
.split{{display:grid;grid-template-columns:1.15fr .85fr;gap:16px}}.metric{{background:#f8fafc;
border:1px solid #edf0f5;border-radius:14px;padding:14px}}.metric strong{{display:block;font-size:1.35rem}}
.muted{{color:var(--muted)}}.eyebrow{{color:var(--muted);font-size:.76rem;font-weight:750;
letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px}}a,button{{background:var(--blue);color:#fff;
padding:10px 15px;border:0;border-radius:10px;text-decoration:none;font:inherit;font-weight:700;cursor:pointer}}
a.secondary,button.secondary{{background:#edf2f8;color:#344054}}button.danger{{background:#fff0ef;color:var(--red)}}
input,textarea{{padding:10px 12px;border:1px solid #cbd3df;border-radius:9px;font:inherit;max-width:100%}}
input[type=number]{{width:110px}}.badge{{display:inline-flex;align-items:center;padding:5px 9px;
border-radius:999px;background:#edf7f3;color:var(--green);font-size:.8rem;font-weight:750}}.badge.wait{{background:#fff6e7;color:var(--amber)}}
.badge.bad{{background:#fff0ef;color:var(--red)}}.notice{{padding:14px 16px;border-radius:13px;margin:0 0 16px;
border:1px solid #b8d7ff;background:#edf6ff;color:#174f91}}.notice.good{{border-color:#b7e2d1;background:#edf9f4;color:#096548}}
.notice.bad{{border-color:#f0c1bd;background:#fff2f1;color:#9c2d24}}.progress-track{{height:10px;background:#e9edf3;
border-radius:999px;overflow:hidden;margin:12px 0 7px}}.progress-fill{{height:100%;background:var(--blue);border-radius:999px}}
.schedule{{padding:16px;border:1px solid var(--line);border-radius:15px;background:#fbfcfe}}.actions{{margin-top:18px}}
.danger-zone{{border-top:1px solid var(--line);padding-top:18px;margin-top:20px}}form{{margin:0}}
@media(max-width:760px){{.grid,.split{{grid-template-columns:1fr}}main{{padding:24px 14px 48px}}.panel{{padding:18px}}}}
</style></head><body><main>{content}</main></body></html>"""

    def _login_page(self, error=""):
        try:
            location = self.control.begin_login()
            action = f'<a href="{html.escape(location)}">Continue with Google</a>'
        except HostedControlError:
            action = "<p>Sign-in is temporarily unavailable.</p>"
        notice = f'<p>{html.escape(error)}</p>' if error else ""
        return self._page("Sign in", f"""
<div class="topbar"><div class="brand"><div class="mark">✉</div><div><h1>Email Scanner</h1>
<div class="muted">Organize mail and prepare replies</div></div></div></div>
<section class="panel"><h2>Sign in</h2><p class="muted">Your website session and Gmail
connection are managed separately.</p>{notice}{action}</section>""")

    @staticmethod
    def _notice(query):
        key = (query.get("notice") or [""])[-1]
        notices = {
            "run-queued": ("A mailbox scan was queued.", ""),
            "backfill-queued": ("Historical scan queued. Progress will appear below.", ""),
            "undo-queued": ("Undo queued. Only the latest run's recorded changes will be removed.", ""),
            "already-running": ("This mailbox already has a scan or undo in progress. No duplicate was queued.", ""),
            "settings-saved": ("Mailbox settings were saved.", "good"),
            "schedule-on": ("Daily scanning is now enabled.", "good"),
            "schedule-off": ("Daily scanning is paused.", ""),
            "disconnected": ("The Gmail account was disconnected from this website.", "good"),
            "connected": ("Gmail connected. Complete the mailbox settings to begin scanning.", "good"),
            "invalid-count": ("Choose a whole number from 10 to 5,000.", "bad"),
            "undo-unavailable": ("There is no completed run available to undo.", "bad"),
            "connect-failed": ("Google could not finish linking that Gmail account. Start again.", "bad"),
            "action-failed": ("That action could not be completed safely. Try again.", "bad"),
        }
        message, style = notices.get(key, ("", ""))
        return f'<div class="notice {style}">{html.escape(message)}</div>' if message else ""

    def _dashboard(self, identity, query=None):
        query = query or {}
        mailboxes = self.store.mailboxes_for_user(identity.user_id)
        cards = []
        refresh = False
        for mailbox in mailboxes:
            from tenant_worker import artifact_directory
            directory = artifact_directory(self.config.state_root, mailbox.id)
            counts = _job_counts(directory, mailbox.last_job_id)
            rollback = latest_summary(directory)
            active = mailbox.last_job_status in {"queued", "running"}
            refresh = refresh or active
            status_label = {
                "queued": "Queued", "running": "Running",
                "succeeded": "Completed", "failed": "Needs attention",
                "cancelled": "Cancelled",
            }.get(mailbox.last_job_status, "No runs yet")
            status_class = (
                "wait" if active else "bad" if mailbox.last_job_status == "failed" else ""
            )
            total = mailbox.requested_count or max(mailbox.processed_count, counts["scanned"])
            percent = (
                min(100, round(mailbox.processed_count / total * 100))
                if total else 0
            )
            group_size = max(1, mailbox.last_job_group_size)
            groups_done = math.ceil(mailbox.processed_count / group_size) if mailbox.processed_count else 0
            groups_total = math.ceil(total / group_size) if total else 0
            remaining = max(0, total - mailbox.processed_count) if active else 0
            error = ""
            if mailbox.last_job_status == "failed":
                error = ('<div class="notice bad">The latest run stopped safely. '
                         'Reconnect Gmail if needed, then try again.</div>')
            progress = f"""
<div class="panel"><div class="mailbox-head"><div><p class="eyebrow">Latest activity</p>
<h2>{html.escape((mailbox.last_job_kind or 'scan').replace('_', ' ').title())}</h2></div>
<span class="badge {status_class}">{status_label}</span></div>{error}
<div class="progress-track"><div class="progress-fill" style="width:{percent}%"></div></div>
<p class="muted">{mailbox.processed_count} of {total or '—'} processed · {percent}%
 · Groups {groups_done}/{groups_total or '—'} · ETA: {html.escape(_eta(mailbox, self.clock()))}</p>
<div class="grid">
<div class="metric"><span class="muted">Scanned</span><strong>{counts['scanned'] or mailbox.processed_count}</strong></div>
<div class="metric"><span class="muted">Labeled</span><strong>{counts['labeled']}</strong></div>
<div class="metric"><span class="muted">Drafted</span><strong>{counts['drafted']}</strong></div>
<div class="metric"><span class="muted">Skipped</span><strong>{counts['skipped']}</strong></div>
<div class="metric"><span class="muted">Failed</span><strong>{counts['failures']}</strong></div>
<div class="metric"><span class="muted">Retried</span><strong>{max(0, mailbox.last_job_attempts - 1)}</strong></div>
</div><p class="muted" style="margin:12px 0 0">Remaining: {remaining}</p></div>""" if mailbox.last_job_status else ""
            setup = "Ready" if mailbox.setup_status == "ready" else "Setup required"
            setup_class = "" if mailbox.setup_status == "ready" else "wait"
            disabled = " disabled" if mailbox.setup_status != "ready" or active else ""
            undo_card = ""
            if rollback is not None and not active:
                undo_card = f"""
<div class="danger-zone"><div class="mailbox-head"><div><h3>Undo last run</h3>
<p class="muted">Remove {rollback['drafts']} drafts and {rollback['labels']} label changes
across {rollback['messages']} emails.</p></div>
<form method="post" action="/undo"><input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}"><input type="hidden" name="group_id" value="{rollback['group_id']}">
<button class="danger" name="confirmation" value="UNDO">Undo last run</button></form></div></div>"""
            cards.append(f"""
<section class="panel"><div class="mailbox-head"><div><p class="eyebrow">Connected mailbox</p>
<h2>{html.escape(mailbox.address)}</h2></div><span class="badge {setup_class}">{setup}</span></div>
<div class="split"><div><h3>Scan new mail</h3><p class="muted">Label and draft replies for newly arrived messages.</p>
<form method="post" action="/run-now" class="row">
<input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<button{disabled}>Run now</button></form></div>
<div><h3>Scan previous emails</h3><p class="muted">Choose between 10 and 5,000 messages.</p>
<form method="post" action="/backfill" class="row"><input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}"><input type="number" name="count" min="10" max="5000" value="100" required>
<button{disabled}>Start scan</button></form></div></div>
<div class="schedule"><div class="mailbox-head"><div><h3>Daily automation</h3>
<p class="muted">{html.escape(str(mailbox.run_at)[:5])} {html.escape(mailbox.timezone)} · Next: {_display_time(mailbox.next_run_at)}<br>
Last successful daily run: {_display_time(mailbox.last_daily_success_at, 'No successful daily run yet')}</p></div>
<form method="post" action="/schedule"><input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}"><input type="hidden" name="enabled" value="{'0' if mailbox.enabled else '1'}">
<button class="secondary">{'Pause' if mailbox.enabled else 'Resume'}</button></form></div></div>
<div class="row actions"><a class="secondary" href="/settings?mailbox_id={mailbox.id}">Settings</a></div>
{undo_card}
<form method="post" action="/disconnect" class="row">
<input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<input name="confirmation" placeholder="Type Gmail address" required>
<button class="danger">Disconnect Gmail</button></form></section>{progress}""")
        if not cards:
            cards.append('<section class="panel"><h2>No Gmail account connected</h2><p class="muted">Link an account to configure labels, drafting, and scheduling.</p></section>')
        return self._page("Dashboard", f"""
<div class="topbar"><div class="brand"><div class="mark">✉</div><div><h1>Email Scanner</h1>
<div class="muted">Signed in as {html.escape(identity.display_email)}</div></div></div><div class="row">
<form method="post" action="/connect"><input type="hidden" name="csrf"
value="{csrf_value(identity)}"><button>Link Gmail account</button></form>
<form method="post" action="/logout"><input type="hidden" name="csrf"
value="{csrf_value(identity)}"><button class="secondary">Sign out</button></form></div></div>
{self._notice(query)}{''.join(cards)}""", refresh=refresh)

    def _settings_page(self, identity, mailbox, *, error=""):
        from tenant_worker import artifact_directory

        directory = artifact_directory(self.config.state_root, mailbox.id)
        try:
            document = json.loads(
                (directory / "account.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            document = {}
        taxonomy = document.get("taxonomy")
        taxonomy = taxonomy if isinstance(taxonomy, list) else []
        labels = "\n".join(
            f"{entry.get('display', '')} | {entry.get('label', '')}"
            for entry in taxonomy if isinstance(entry, dict)
            and entry.get("slug") != "other"
        )
        drafting = document.get("ai_drafting")
        drafting = drafting if isinstance(drafting, dict) else {}
        notice = f"<p>{html.escape(error)}</p>" if error else ""
        return self._page("Mailbox settings", f"""
<div class="topbar"><div class="brand"><div class="mark">✉</div><div><h1>Mailbox settings</h1>
<div class="muted">{html.escape(mailbox.address)}</div></div></div></div>
<section class="panel">{notice}
<form method="post" action="/settings">
<input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<p><label>Labels<br><textarea name="labels" rows="7" required>{html.escape(labels)}</textarea></label></p>
<p><label>Timezone <input name="timezone" value="{html.escape(str(document.get('timezone') or 'UTC'))}" required></label></p>
<p><label>Daily time <input type="time" name="run_at" value="{html.escape(str(mailbox.run_at)[:5])}" required></label></p>
<p><label>Name <input name="display_name" value="{html.escape(str(drafting.get('display_name') or ''))}" required></label></p>
<p><label>Role <input name="role" value="{html.escape(str(drafting.get('role') or ''))}"></label></p>
<p><label>Organization <input name="organization" value="{html.escape(str(drafting.get('organization') or ''))}"></label></p>
<p><label>Signature <input name="signature" value="{html.escape(str(drafting.get('signature') or ''))}" required></label></p>
<p><label>Messages per daily run <input type="number" name="max_scan" min="1" max="2000" value="2000" required></label></p>
<input type="hidden" name="confirm_unsent_drafts" value="yes">
<button>Save settings</button> <a href="/">Cancel</a></form></section>""")

    def __call__(self, environ, start_response):
        path = str(environ.get("PATH_INFO") or "/")
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        head = method == "HEAD"
        identity = self._identity(environ)

        if path == "/login" and method in {"GET", "HEAD"}:
            if identity is not None:
                return self._redirect(start_response, "/")
            query = parse_qs(str(environ.get("QUERY_STRING", "")))
            error = (
                "Google sign-in did not finish. Start again."
                if (query.get("connect") or [""])[-1] == "failed" else ""
            )
            return self._respond(
                start_response, "200 OK", self._login_page(error), head=head
            )
        if path == "/oauth/callback" and method == "GET":
            try:
                if identity is None:
                    result = self.control.complete_login(
                        environ.get("QUERY_STRING", "")
                    )
                    user_id = self.store.create_or_get_user(
                        result.issuer, result.subject, result.email
                    )
                    issued = self.store.issue_session(user_id, now=self.clock())
                    return self._redirect(
                        start_response, "/",
                        [("Set-Cookie", self._cookie(issued.token))],
                    )
                self.control.complete_mailbox_connect(
                    environ.get("QUERY_STRING", ""), identity.user_id
                )
                return self._redirect(start_response, "/?notice=connected")
            except (HostedControlError, TenantAccessDenied):
                location = (
                    "/?notice=connect-failed" if identity is not None
                    else "/login?connect=failed"
                )
                return self._redirect(start_response, location)
        if identity is None:
            return self._redirect(start_response, "/login")

        if path == "/settings" and method in {"GET", "HEAD"}:
            query = parse_qs(str(environ.get("QUERY_STRING", "")))
            try:
                mailbox_id = uuid.UUID((query.get("mailbox_id") or [""])[-1])
                mailbox = self.store.mailbox_view_for_user(
                    identity.user_id, mailbox_id
                )
            except (ValueError, TenantAccessDenied):
                return self._redirect(start_response, "/")
            return self._respond(
                start_response, "200 OK",
                self._settings_page(identity, mailbox), head=head,
            )

        if path in {"/connect", "/logout", "/disconnect", "/run-now",
                    "/backfill", "/undo", "/schedule", "/settings"} \
                and method == "POST":
            form = self._form(environ)
            if form is None or not hmac.compare_digest(
                    str(form.get("csrf", "")), csrf_value(identity)):
                return self._respond(
                    start_response, "403 Forbidden",
                    self._page("Request refused", "<h1>Request refused</h1>"),
                )
            if path == "/connect":
                return self._redirect(
                    start_response,
                    self.control.begin_mailbox_connect(identity.user_id),
                )
            if path == "/logout":
                self.store.revoke_session(
                    identity.session_id, identity.user_id, now=self.clock()
                )
                return self._redirect(
                    start_response, "/login",
                    [("Set-Cookie", self._cookie(clear=True))],
                )
            try:
                mailbox_id = uuid.UUID(str(form.get("mailbox_id", "")))
                if path == "/settings":
                    import hosted_settings
                    from tenant_settings import save_mailbox_settings

                    try:
                        save_mailbox_settings(
                            self.store, self.config.state_root,
                            identity.user_id, mailbox_id, form,
                            now=self.clock(),
                        )
                    except hosted_settings.SettingsError as exc:
                        mailbox = self.store.mailbox_view_for_user(
                            identity.user_id, mailbox_id
                        )
                        return self._respond(
                            start_response, "400 Bad Request",
                            self._settings_page(
                                identity, mailbox, error=str(exc)
                            ),
                        )
                    return self._redirect(
                        start_response, "/?notice=settings-saved"
                    )
                if path == "/disconnect":
                    self.control.disconnect_mailbox(
                        identity.user_id, mailbox_id,
                        form.get("confirmation", ""),
                    )
                    return self._redirect(
                        start_response, "/?notice=disconnected"
                    )
                if path == "/schedule":
                    enabled = str(form.get("enabled", "")) == "1"
                    self.store.set_mailbox_enabled(
                        identity.user_id, mailbox_id, enabled, now=self.clock()
                    )
                    return self._redirect(
                        start_response,
                        f"/?notice=schedule-{'on' if enabled else 'off'}",
                    )
                if path == "/backfill":
                    try:
                        count = int(str(form.get("count", "")))
                    except ValueError:
                        count = 0
                    if not 10 <= count <= 5000:
                        return self._redirect(
                            start_response, "/?notice=invalid-count"
                        )
                    job_id = self.store.enqueue_job_if_idle(
                        identity.user_id, mailbox_id, "backfill",
                        f"backfill:{uuid.uuid4()}", requested_count=count,
                    )
                    notice = "backfill-queued" if job_id else "already-running"
                    return self._redirect(
                        start_response, f"/?notice={notice}"
                    )
                if path == "/undo":
                    from tenant_worker import artifact_directory

                    directory = artifact_directory(
                        self.config.state_root, mailbox_id
                    )
                    summary = latest_summary(directory)
                    requested_group = str(form.get("group_id", ""))
                    if (str(form.get("confirmation", "")).upper() != "UNDO"
                            or summary is None
                            or requested_group != summary.get("group_id")):
                        return self._redirect(
                            start_response, "/?notice=undo-unavailable"
                        )
                    job_id = self.store.enqueue_job_if_idle(
                        identity.user_id, mailbox_id, "undo",
                        f"undo:{requested_group}:{uuid.uuid4()}",
                        requested_count=max(1, int(summary["messages"])),
                    )
                    notice = "undo-queued" if job_id else "already-running"
                    return self._redirect(
                        start_response, f"/?notice={notice}"
                    )
                job_id = self.store.enqueue_job_if_idle(
                    identity.user_id, mailbox_id, "incoming",
                    f"manual:{uuid.uuid4()}",
                )
                notice = "run-queued" if job_id else "already-running"
                return self._redirect(start_response, f"/?notice={notice}")
            except (ValueError, HostedControlError, TenantAccessDenied):
                return self._redirect(
                    start_response, "/?notice=action-failed"
                )

        if path == "/" and method in {"GET", "HEAD"}:
            query = parse_qs(str(environ.get("QUERY_STRING", "")))
            return self._respond(
                start_response, "200 OK", self._dashboard(identity, query),
                head=head,
            )
        return self._respond(
            start_response, "404 Not Found",
            self._page("Not found", "<h1>Page not found</h1>"), head=head,
        )
