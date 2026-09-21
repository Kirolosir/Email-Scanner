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
from hosted_dashboard import (
    COUNT_KEYS,
    HTML_HEADERS,
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    HostedDashboardApp,
    _escape,
    _safe_coach_profile,
    _safe_counts,
    _safe_labels,
    _safe_review_queue,
    _render_review_queue,
)
from rollback_journal import latest_summary
from tenant_store import TenantAccessDenied, csrf_value


MAX_FORM_BYTES = 8192
SUMMARY_KEYS = tuple(COUNT_KEYS)


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
        page = HostedDashboardApp._page(title, content)
        if refresh:
            page = page.replace(
                '<meta name="viewport"',
                '<meta http-equiv="refresh" content="4">\n<meta name="viewport"',
                1,
            )
        return page

    def _login_page(self, error=""):
        try:
            location = self.control.begin_login()
            action = (
                f'<a class="google-button" href="{html.escape(location)}">'
                '<span aria-hidden="true">G</span>Continue with Google</a>'
            )
        except HostedControlError:
            action = "<p>Sign-in is temporarily unavailable.</p>"
        notice = f'<p class="notice bad">{html.escape(error)}</p>' if error else ""
        return self._page("Sign in", f"""
<main class="login-shell"><section class="login-card"><div class="mark">ES</div>
<p class="eyebrow">Email Scanner</p><h1>Continue with Google</h1>
<p class="lede">Sign in to your private dashboard. The app will then continue
directly to Gmail permission so you can link your mailbox.</p>{notice}{action}
<p class="browser-note">Google uses two secure steps: website identity, then
Gmail access. Each person receives an isolated dashboard and mailbox.</p></section></main>""")

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
            "already-connected": ("A Gmail account is already linked. Disconnect it before linking a different account.", "good"),
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
        requested = (query.get("mailbox_id") or [""])[-1]
        mailbox = next(
            (item for item in mailboxes if str(item.id) == requested),
            mailboxes[0] if mailboxes else None,
        )
        csrf = csrf_value(identity)
        connect_action = "" if mailboxes else f"""
<form method="post" action="/connect"><input type="hidden" name="csrf" value="{csrf}">
<button class="ghost" type="submit">Link Gmail account</button></form>"""
        header = f"""
<header class="topbar"><a class="brand" href="/"><span class="mark small">ES</span>
<span>Email Scanner</span></a><div class="top-actions">
<span class="ghost-link">{html.escape(identity.display_email)}</span>
{connect_action}
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}">
<button class="ghost" type="submit">Sign out</button></form></div></header>"""
        if mailbox is None:
            return self._page("Dashboard", f"""{header}<main class="workspace">
{self._notice(query)}<section class="account-hero"><div><p class="eyebrow">Connected inbox</p>
<h1>Finish connecting Gmail</h1><p class="lede">Website sign-in is complete, but Gmail access has not been linked yet.
Link one Gmail account to activate scans, historical backfill, labels, drafts, daily scheduling,
run history, and undo.</p></div><div class="hero-actions"><span class="status"><i></i>Step 2 of 2</span>
<form method="post" action="/connect"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit">Link Gmail account</button></form></div></section>
<section class="overview-grid"><article class="panel schedule"><p class="eyebrow">Next daily run</p>
<h2>Connect Gmail first</h2><p>Your own schedule appears here.</p></article>
<article class="panel health"><p class="eyebrow">Gmail connection</p><h2>Not connected</h2>
<p>Credentials are isolated for each person and mailbox.</p></article>
<article class="panel last-run"><p class="eyebrow">Last run</p><h2>Not run yet</h2>
<p>Run results and recovery controls appear after setup.</p></article></section></main>""")

        from tenant_worker import artifact_directory
        directory = artifact_directory(self.config.state_root, mailbox.id)
        counts = _job_counts(directory, mailbox.last_job_id)
        if not any(counts.values()):
            counts.update(_safe_counts(directory))
        labels = _safe_labels(directory)
        review_rows = _safe_review_queue(directory)
        coach = _safe_coach_profile(directory)
        rollback = latest_summary(directory)
        active = mailbox.last_job_status in {"queued", "running"}
        ready = mailbox.setup_status == "ready"
        total = mailbox.requested_count or max(mailbox.processed_count, counts.get("scanned", 0))
        percent = min(100, round(mailbox.processed_count / total * 100)) if total else 0
        group_size = max(1, mailbox.last_job_group_size)
        groups_done = math.ceil(mailbox.processed_count / group_size) if mailbox.processed_count else 0
        groups_total = math.ceil(total / group_size) if total else 0
        progress = ""
        if mailbox.last_job_status:
            progress = f"""<section class="panel run-progress" aria-live="polite">
<div class="section-head"><div><p class="eyebrow">Latest activity</p>
<h2>{_escape((mailbox.last_job_kind or 'scan').replace('_', ' ').title())}: {_escape(mailbox.last_job_status.title())}</h2></div>
<span class="count-badge">{percent}%</span></div><progress value="{mailbox.processed_count}" max="{total or 1}"></progress>
<p>{mailbox.processed_count} of {total or '—'} processed · Groups {groups_done}/{groups_total or '—'}
 · ETA: {_escape(_eta(mailbox, self.clock()))}</p></section>"""
        failure = ""
        if mailbox.last_job_status == "failed":
            failure = """<section class="failure-alert" role="alert"><div>
<p class="eyebrow">Run needs attention</p><h2>The latest run stopped safely</h2>
<p>No email was sent. Review the mailbox settings or reconnect Gmail, then try again.</p></div>
<a class="secondary" href="/settings?mailbox_id=%s">Review settings</a></section>""" % mailbox.id

        switcher = ""
        if len(mailboxes) > 1:
            links = "".join(
                f'<a class="secondary" href="/?mailbox_id={item.id}">{html.escape(item.address)}</a>'
                for item in mailboxes
            )
            switcher = f'<section class="panel"><div class="section-head"><div><p class="eyebrow">Your mailboxes</p><h2>Switch inbox</h2></div></div><div class="section-actions">{links}</div></section>'

        settings_url = f"/settings?mailbox_id={mailbox.id}"
        disabled = " disabled" if not ready or active else ""
        setup_notice = "" if ready else f"""<p class="notice progress"><strong>Finish mailbox setup.</strong>
Choose labels, schedule, and reply style before the first scan.
<a href="{settings_url}">Open settings</a></p>"""
        history = f"""<section class="panel history-run"><div><p class="eyebrow">Inbox catch-up</p>
<h2>Start background backfill</h2><p>Scan previous emails in resumable 200-message groups.
Every replyable email is labeled and receives an unsent draft. New-mail processing remains available
between groups.</p></div><form method="post" action="/backfill"><input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}"><label for="message_count">Previous messages</label>
<div class="history-controls"><input id="message_count" name="count" type="number" min="10" max="5000" value="100" required>
<button type="submit"{disabled}>Start backfill</button></div></form></section>"""
        undo = ""
        if rollback is not None and not active:
            undo = f"""<section class="panel undo-run"><div><p class="eyebrow">Previous run</p>
<h2>Undo drafts and labels</h2><p>Undo {rollback['drafts']} drafts and {rollback['labels']} label changes
across {rollback['messages']} emails. The full run is included with no item limit.</p></div>
<a class="secondary danger-link" href="/undo?mailbox_id={mailbox.id}">Review undo</a></section>"""

        count_labels = {
            "drafted": "drafts created", "drafts_existing": "existing drafts preserved",
            "drafts_rebuilt": "missing drafts rebuilt", "no_reply_address": "no reply address",
            "fetch_failures": "email retrieval failures", "generation_fallbacks": "generation fallbacks",
            "retry_queued": "queued for retry", "gmail_requests": "Gmail requests",
            "gmail_retries": "Gmail retries", "gmail_quota_units": "Gmail quota units",
            "gemini_calls": "generation calls", "gemini_input_tokens": "input tokens",
            "gemini_output_tokens": "output tokens", "estimated_cost_microusd": "estimated cost",
            "duration_seconds": "run time (seconds)", "average_duration_seconds": "average run time",
            "backup_verified": "verified backups", "backup_failures": "backup failures",
        }
        coverage_keys = {"drafted", "drafts_existing", "drafts_rebuilt", "no_reply_address",
                         "fetch_failures", "generation_fallbacks", "retry_queued"}
        usage_keys = {"gmail_requests", "gmail_retries", "gmail_quota_units", "gemini_calls",
                      "gemini_input_tokens", "gemini_output_tokens", "estimated_cost_microusd",
                      "duration_seconds", "average_duration_seconds", "backup_verified", "backup_failures"}

        def cards(keys, *, exclude=False):
            selected = []
            for key, value in counts.items():
                include = key not in keys if exclude else key in keys
                if not include or not value:
                    continue
                displayed = f"${value / 1_000_000:.4f}" if key == "estimated_cost_microusd" else value
                selected.append(f'<div class="metric"><span>{_escape(count_labels.get(key, key.replace("_", " ")))}</span><strong>{_escape(displayed)}</strong></div>')
            return "".join(selected) or '<p class="empty">Results will appear after the first run.</p>'

        label_rows = "".join(
            '<li><div><strong>' + _escape(item["display"]) + '</strong><span>'
            + _escape(item["name"]) + '</span></div><span class="tag">'
            + ("labels + drafts" if item["drafting"] else "labels only") + '</span></li>'
            for item in labels
        ) or '<li class="empty">Finish settings to prepare Gmail labels.</li>'
        coach_name = coach.get("display_name") or "Coach profile"
        coach_context = " · ".join(value for value in (coach.get("role"), coach.get("organization")) if value) \
            or "Add your role and program so replies sound like you."
        status_text = "Active" if ready and mailbox.enabled else "Setup required" if not ready else "Paused"
        run_status = mailbox.last_job_status.title() if mailbox.last_job_status else "Not run yet"
        finished = _display_time(mailbox.last_job_finished_at, "No completed run yet")
        remaining = max(0, total - mailbox.processed_count) if active else 0
        activity_values = (
            ("scanned", counts.get("scanned", mailbox.processed_count)),
            ("classified", counts.get("classified", 0)),
            ("labeled", counts.get("labeled", 0)),
            ("drafted", counts.get("drafted", 0)),
            ("skipped", counts.get("skipped", 0)),
            ("failed", counts.get("failures", 0)),
            ("retried", max(0, mailbox.last_job_attempts - 1)),
            ("remaining", remaining),
        )
        activity_cards = "".join(
            f'<div class="metric"><span>{label}</span><strong>{value}</strong></div>'
            for label, value in activity_values
        )

        return self._page("Dashboard", f"""{header}<main class="workspace">
{self._notice(query)}{setup_notice}{failure}<section class="account-hero"><div>
<p class="eyebrow">Connected inbox</p><h1>{html.escape(mailbox.address)}</h1>
<p class="lede">Email Scanner organizes eligible mail and prepares unsent Gmail drafts for review.
Nothing is sent automatically.</p></div><div class="hero-actions"><span class="status {'good' if ready else ''}"><i></i>{status_text}</span>
<a class="secondary" href="{settings_url}">Edit labels &amp; schedule</a>
<form method="post" action="/run-now"><input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}"><button type="submit"{disabled}>Scan new mail</button></form></div></section>
{switcher}{progress}<section class="overview-grid"><article class="panel schedule"><p class="eyebrow">Next daily run</p>
<h2>{_display_time(mailbox.next_run_at)}</h2><p>Up to {mailbox.max_scan} recent messages at {str(mailbox.run_at)[:5]} {html.escape(mailbox.timezone)}.</p>
<form method="post" action="/schedule"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="mailbox_id" value="{mailbox.id}">
<input type="hidden" name="enabled" value="{'0' if mailbox.enabled else '1'}"><button class="secondary" type="submit">{'Pause' if mailbox.enabled else 'Resume'} daily run</button></form></article>
<article class="panel health"><p class="eyebrow">Gmail connection</p><h2>Connected securely</h2>
<p>Last authorized {_display_time(mailbox.last_authorized_at, 'during account setup')}</p></article>
<article class="panel last-run"><p class="eyebrow">Last run</p><h2>{run_status}</h2><p>{finished}</p></article></section>
{history}{undo}<section class="content-grid"><article class="panel results"><div class="section-head"><div><p class="eyebrow">Activity</p>
<h2>Latest run results</h2></div></div><div class="metrics">{activity_cards}</div></article>
<article class="panel labels"><div class="section-head"><div><p class="eyebrow">Rules</p><h2>Your Gmail labels</h2></div>
<div class="section-actions"><span class="count-badge">{len(labels)}</span><a class="secondary" href="{settings_url}">Edit labels</a></div></div><ul>{label_rows}</ul></article></section>
<section class="content-grid"><article class="panel results"><div class="section-head"><div><p class="eyebrow">Coverage</p><h2>Draft coverage</h2></div></div>
<div class="metrics">{cards(coverage_keys)}</div></article><article class="panel results"><div class="section-head"><div><p class="eyebrow">Reliability</p>
<h2>Usage and recovery</h2></div></div><div class="metrics">{cards(usage_keys)}</div></article></section>
<section class="panel coach-card"><div><p class="eyebrow">Coach voice</p><h2>{_escape(coach_name)}</h2><p>{_escape(coach_context)}</p></div>
<a class="secondary" href="{settings_url}">Edit profile</a></section>
<section class="panel review-queue"><div class="section-head"><div><p class="eyebrow">Review queue</p><h2>Replies ready in Gmail</h2>
<p>Review, edit, and send each response from Gmail.</p></div><a class="secondary" href="https://mail.google.com/mail/u/0/#drafts" target="_blank" rel="noopener noreferrer">Open all drafts</a></div>
<div class="draft-list">{_render_review_queue(review_rows)}</div></section></main>""", refresh=active)

    def _settings_page(self, identity, mailbox, *, error="", form=None,
                       connected=False):
        import hosted_settings
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
        ) or ("Recruit intro | Recruits/Intro\nRecruit update | Recruits/Update\n"
              "Parent | Recruits/Parent\nCoach | Coaches\nCamp inquiry | Camps")
        drafting = document.get("ai_drafting")
        drafting = drafting if isinstance(drafting, dict) else {}
        values = {
            "labels": labels,
            "timezone": str(document.get("timezone") or mailbox.timezone or "UTC"),
            "run_at": str(mailbox.run_at)[:5],
            "display_name": str(drafting.get("display_name") or ""),
            "role": str(drafting.get("role") or ""),
            "organization": str(drafting.get("organization") or ""),
            "signature": str(drafting.get("signature") or ""),
            "draft_guidance": str(drafting.get("default_guidance")
                                  or hosted_settings.DEFAULT_DRAFT_GUIDANCE),
            "max_scan": str(mailbox.max_scan),
        }
        if form:
            values.update(form)
        fields = {key: html.escape(str(value)) for key, value in values.items()}
        notice = f'<p class="notice bad">{html.escape(error)}</p>' if error else ""
        if connected and not error:
            notice = (
                '<p class="notice good">Gmail connected securely. Review '
                'these settings to activate scanning and daily runs.</p>'
            )
        csrf = csrf_value(identity)
        return self._page("Settings", f"""
<header class="topbar"><a class="brand" href="/"><span class="mark small">ES</span>
<span>Email Scanner</span></a><div class="top-actions"><a class="ghost-link" href="/?mailbox_id={mailbox.id}">Dashboard</a>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="ghost">Sign out</button></form></div></header>
<main class="workspace settings-shell"><section class="account-hero compact"><div><p class="eyebrow">Inbox settings</p>
<h1>Shape your daily assistant</h1><p class="lede">Choose the labels, schedule, batch size, and reply style for {html.escape(mailbox.address)}.</p></div></section>
{notice}<form class="settings-form" method="post" action="/settings"><input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="mailbox_id" value="{mailbox.id}">
<section class="panel form-section"><div class="form-copy"><p class="eyebrow">1 · Organize</p><h2>Gmail labels</h2>
<p>Enter one label per line as <strong>Display name | Gmail label</strong>. Other is added automatically.</p></div>
<div><label for="labels">Labels, up to 12</label><textarea id="labels" name="labels" rows="8" required spellcheck="false">{fields['labels']}</textarea>
<p class="field-note">Example: Recruit intro | Recruits/Intro</p></div></section>
<section class="panel form-section"><div class="form-copy"><p class="eyebrow">2 · Schedule</p><h2>Daily run</h2>
<p>Choose when this mailbox checks new messages and how many it can process.</p></div><div class="field-grid">
<div><label for="run_at">Start time</label><input id="run_at" name="run_at" type="time" value="{fields['run_at']}" required></div>
<div><label for="timezone">Timezone</label><input id="timezone" name="timezone" value="{fields['timezone']}" required autocomplete="off">
<p class="field-note">Use an IANA city-based timezone name or UTC.</p></div>
<div><label for="max_scan">Messages scanned</label><input id="max_scan" name="max_scan" type="number" min="1" max="2000" value="{fields['max_scan']}" required>
<p class="field-note">Every eligible message receives a label and an unsent draft.</p></div></div></section>
<section class="panel form-section"><div class="form-copy"><p class="eyebrow">3 · Reply profile</p><h2>Your voice and program</h2>
<p>Provide the context used to prepare replies. Every response remains an unsent Gmail draft.</p></div><div>
<label for="display_name">Your name</label><input id="display_name" name="display_name" maxlength="120" value="{fields['display_name']}" required>
<div class="field-grid coach-fields"><div><label for="role">Role</label><input id="role" name="role" maxlength="120" value="{fields['role']}" placeholder="Head Coach"></div>
<div><label for="organization">School or program</label><input id="organization" name="organization" maxlength="160" value="{fields['organization']}"></div></div>
<label for="signature">Draft signature</label><textarea id="signature" name="signature" rows="3" maxlength="500" required>{fields['signature']}</textarea>
<label for="draft_guidance">How replies should sound</label><textarea id="draft_guidance" name="draft_guidance" rows="5" maxlength="1200" required>{fields['draft_guidance']}</textarea>
<p class="field-note">Describe your tone, the information senders should provide, and the next steps you usually suggest.</p></div></section>
<section class="panel confirmation"><label class="check-row"><input type="checkbox" name="confirm_unsent_drafts" value="yes" required>
<span><strong>I approve these labels and generated drafts.</strong> Responses stay unsent until I review and send them.</span></label>
<div class="save-row"><a href="/?mailbox_id={mailbox.id}">Cancel</a><button type="submit">Save and prepare labels</button></div></section></form>
<section class="panel danger-zone"><div><p class="eyebrow">Disconnect</p><h2>Remove this Gmail account</h2>
<p>This revokes access, destroys the stored credential, and stops future runs for this mailbox only.</p></div>
<form method="post" action="/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="mailbox_id" value="{mailbox.id}">
<label for="confirmation">Type {html.escape(mailbox.address)} to confirm</label><div class="disconnect-row"><input id="confirmation" name="confirmation" type="email" required autocomplete="off">
<button class="danger" type="submit">Disconnect Gmail</button></div></form></section></main>""")

    def _undo_page(self, identity, mailbox, summary):
        csrf = csrf_value(identity)
        return self._page("Undo previous run", f"""
<header class="topbar"><a class="brand" href="/?mailbox_id={mailbox.id}"><span class="mark small">ES</span><span>Email Scanner</span></a>
<a class="ghost-link" href="/?mailbox_id={mailbox.id}">Cancel</a></header><main class="workspace settings-shell">
<section class="panel danger-zone undo-confirm"><div><p class="eyebrow">Confirm rollback</p><h1>Undo the previous run?</h1>
<p>This removes {summary['labels']} labels added by that run and moves {summary['drafts']} drafts to Gmail Trash across
{summary['messages']} emails. The entire run is included, regardless of size. No email will be sent.</p></div>
<form method="post" action="/undo"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="mailbox_id" value="{mailbox.id}">
<input type="hidden" name="group_id" value="{html.escape(str(summary['group_id']))}"><label for="undo_confirmation">Type UNDO to continue</label>
<input id="undo_confirmation" name="confirmation" autocomplete="off" required><button class="danger" type="submit">Undo previous run</button></form>
</section></main>""")

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
                        start_response, "/link-gmail",
                        [("Set-Cookie", self._cookie(issued.token))],
                    )
                mailbox = self.control.complete_mailbox_connect(
                    environ.get("QUERY_STRING", ""), identity.user_id
                )
                return self._redirect(
                    start_response,
                    f"/settings?mailbox_id={mailbox.id}&connected=1",
                )
            except (HostedControlError, TenantAccessDenied):
                location = (
                    "/?notice=connect-failed" if identity is not None
                    else "/login?connect=failed"
                )
                return self._redirect(start_response, location)
        if identity is None:
            return self._redirect(start_response, "/login")

        if path == "/link-gmail" and method in {"GET", "HEAD"}:
            mailboxes = self.store.mailboxes_for_user(identity.user_id)
            if mailboxes:
                return self._redirect(
                    start_response,
                    f"/?mailbox_id={mailboxes[0].id}"
                    "&notice=already-connected",
                )
            try:
                location = self.control.begin_mailbox_connect(identity.user_id)
            except HostedControlError:
                return self._redirect(
                    start_response, "/?notice=connect-failed"
                )
            return self._redirect(start_response, location)

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
                self._settings_page(
                    identity, mailbox,
                    connected=(query.get("connected") or [""])[-1] == "1",
                ), head=head,
            )

        if path == "/undo" and method in {"GET", "HEAD"}:
            query = parse_qs(str(environ.get("QUERY_STRING", "")))
            try:
                mailbox_id = uuid.UUID((query.get("mailbox_id") or [""])[-1])
                mailbox = self.store.mailbox_view_for_user(
                    identity.user_id, mailbox_id
                )
                from tenant_worker import artifact_directory

                summary = latest_summary(artifact_directory(
                    self.config.state_root, mailbox_id
                ))
                if summary is None:
                    raise ValueError("no undo boundary")
            except (ValueError, TenantAccessDenied):
                return self._redirect(
                    start_response, "/?notice=undo-unavailable"
                )
            return self._respond(
                start_response, "200 OK",
                self._undo_page(identity, mailbox, summary), head=head,
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
                mailboxes = self.store.mailboxes_for_user(identity.user_id)
                if mailboxes:
                    return self._redirect(
                        start_response,
                        f"/?mailbox_id={mailboxes[0].id}"
                        "&notice=already-connected",
                    )
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
                                identity, mailbox, error=str(exc), form=form
                            ),
                        )
                    return self._redirect(
                        start_response,
                        f"/?mailbox_id={mailbox_id}&notice=settings-saved",
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
                        f"/?mailbox_id={mailbox_id}&notice=schedule-"
                        f"{'on' if enabled else 'off'}",
                    )
                if path == "/backfill":
                    try:
                        count = int(str(form.get("count", "")))
                    except ValueError:
                        count = 0
                    if not 10 <= count <= 5000:
                        return self._redirect(
                            start_response,
                            f"/?mailbox_id={mailbox_id}&notice=invalid-count",
                        )
                    job_id = self.store.enqueue_job_if_idle(
                        identity.user_id, mailbox_id, "backfill",
                        f"backfill:{uuid.uuid4()}", requested_count=count,
                    )
                    notice = "backfill-queued" if job_id else "already-running"
                    return self._redirect(
                        start_response,
                        f"/?mailbox_id={mailbox_id}&notice={notice}",
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
                            start_response,
                            f"/?mailbox_id={mailbox_id}&notice=undo-unavailable",
                        )
                    job_id = self.store.enqueue_job_if_idle(
                        identity.user_id, mailbox_id, "undo",
                        f"undo:{requested_group}:{uuid.uuid4()}",
                        requested_count=max(1, int(summary["messages"])),
                    )
                    notice = "undo-queued" if job_id else "already-running"
                    return self._redirect(
                        start_response,
                        f"/?mailbox_id={mailbox_id}&notice={notice}",
                    )
                job_id = self.store.enqueue_job_if_idle(
                    identity.user_id, mailbox_id, "incoming",
                    f"manual:{uuid.uuid4()}",
                )
                notice = "run-queued" if job_id else "already-running"
                return self._redirect(
                    start_response,
                    f"/?mailbox_id={mailbox_id}&notice={notice}",
                )
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
