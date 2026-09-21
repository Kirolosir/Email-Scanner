"""WSGI account boundary for the PostgreSQL-backed hosted dashboard."""
from __future__ import annotations

import datetime as dt
import hmac
import html
import json
import uuid
from urllib.parse import parse_qs, urlencode

from hosted_control import HostedControlError
from hosted_dashboard import HTML_HEADERS, SESSION_COOKIE, SESSION_MAX_AGE_SECONDS
from tenant_store import TenantAccessDenied, csrf_value


MAX_FORM_BYTES = 8192


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
    def _page(title, content):
        return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(title)} · Email Scanner</title>
<style>
body{{font:16px system-ui;margin:0;background:#f5f7fb;color:#172033}}
main{{max-width:920px;margin:0 auto;padding:48px 20px}}section{{background:white;
padding:24px;border:1px solid #dce3ee;border-radius:18px;margin:16px 0}}
a,button{{background:#1769e0;color:white;padding:11px 16px;border:0;
border-radius:10px;text-decoration:none;font-weight:650}}button.secondary{{background:#526071}}
.row{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
.muted{{color:#667085}}input{{padding:10px;border:1px solid #b9c3d1;border-radius:8px}}
</style></head><body><main>{content}</main></body></html>"""

    def _login_page(self, error=""):
        try:
            location = self.control.begin_login()
            action = f'<a href="{html.escape(location)}">Continue with Google</a>'
        except HostedControlError:
            action = "<p>Sign-in is temporarily unavailable.</p>"
        notice = f'<p>{html.escape(error)}</p>' if error else ""
        return self._page("Sign in", f"""
<section><h1>Sign in</h1><p class="muted">Your website session and Gmail
connection are managed separately.</p>{notice}{action}</section>""")

    def _dashboard(self, identity):
        mailboxes = self.store.mailboxes_for_user(identity.user_id)
        cards = []
        for mailbox in mailboxes:
            progress = ""
            if mailbox.last_job_status:
                total = mailbox.requested_count or "—"
                progress = (
                    f"<p>Latest job: {html.escape(mailbox.last_job_status)} · "
                    f"{mailbox.processed_count}/{total}</p>"
                )
            setup = (
                "Ready" if mailbox.setup_status == "ready"
                else "Setup required"
            )
            cards.append(f"""
<section><h2>{html.escape(mailbox.address)}</h2>
<p>Mailbox status: {setup}</p>
<p>Daily run: {html.escape(str(mailbox.run_at))} {html.escape(mailbox.timezone)}
 · {'enabled' if mailbox.enabled else 'paused'}</p>{progress}
<form method="post" action="/run-now" class="row">
<input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<button>Run now</button>
<a href="/settings?mailbox_id={mailbox.id}">Settings</a></form>
<form method="post" action="/disconnect" class="row">
<input type="hidden" name="csrf" value="{csrf_value(identity)}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<input name="confirmation" placeholder="Type Gmail address" required>
<button class="secondary">Disconnect Gmail</button></form></section>""")
        if not cards:
            cards.append("<section><p>No Gmail account connected.</p></section>")
        return self._page("Dashboard", f"""
<div class="row"><h1>Mailboxes</h1>
<form method="post" action="/connect"><input type="hidden" name="csrf"
value="{csrf_value(identity)}"><button>Link Gmail account</button></form>
<form method="post" action="/logout"><input type="hidden" name="csrf"
value="{csrf_value(identity)}"><button class="secondary">Sign out</button></form>
</div><p class="muted">Signed in as {html.escape(identity.display_email)}</p>
{''.join(cards)}""")

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
<section><h1>Mailbox settings</h1><p>{html.escape(mailbox.address)}</p>{notice}
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
            return self._respond(
                start_response, "200 OK", self._login_page(), head=head
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
                return self._redirect(start_response, "/?connected=1")
            except (HostedControlError, TenantAccessDenied):
                return self._redirect(start_response, "/login?connect=failed")
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
                    "/settings"} \
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
                    return self._redirect(start_response, "/?saved=1")
                if path == "/disconnect":
                    self.control.disconnect_mailbox(
                        identity.user_id, mailbox_id,
                        form.get("confirmation", ""),
                    )
                    return self._redirect(start_response, "/?disconnected=1")
                request_key = f"manual:{uuid.uuid4()}"
                self.store.enqueue_job(
                    identity.user_id, mailbox_id, "incoming", request_key
                )
                return self._redirect(start_response, "/?run=requested")
            except (ValueError, HostedControlError, TenantAccessDenied):
                return self._redirect(start_response, "/?action=failed")

        if path == "/" and method in {"GET", "HEAD"}:
            return self._respond(
                start_response, "200 OK", self._dashboard(identity), head=head
            )
        return self._respond(
            start_response, "404 Not Found",
            self._page("Not found", "<h1>Page not found</h1>"), head=head,
        )
