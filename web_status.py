"""Read-only localhost status page for triage runs.

Renders only artifacts that were already designed to be safe to display: the
PII-free run status document and the PII-minimized review reports. It makes no
Gmail or Gemini contact, holds no credential, and writes nothing.

DELIBERATE NON-IMPORTS. This module imports no project module at all, only the
standard library. That is a load-bearing property, not tidiness: importing
`readiness` pulls in gmail_auth, gemini_client, googleapiclient and
google.oauth2 transitively, which would place the whole OAuth and model client
stack inside a long-lived listening process. Anything needing those must run as
a separate short-lived subprocess instead, so the credential surface stays where
the CLI already keeps it. test_web_status.py enforces this at runtime, not just
by reading the import list.

DELIBERATE NON-EXECUTION. This module also starts no subprocess. Readiness is
displayed from a snapshot written by `check_readiness.py --json --json-output`,
not computed on demand, for two reasons. A readiness run executes the whole
test suite twice and takes tens of seconds, which no page load should wait on.
More importantly, any page a browser visits can cause a request here - Host
validation stops a hostile origin READING the response, not causing the GET -
so work triggered per request is work an outside page can amplify. Reading a
file is bounded; spawning an interpreter is not.

DELIBERATE NON-REUSE from oauth_broker.py. The routing shape, the GET-only
gate, and the response-header helper are modelled on that module. Its
`_scheme()`/X-Forwarded-Proto handling is deliberately NOT copied: that exists
because the broker sits behind a hosting proxy, and the header is
client-controllable, so honouring it on loopback would let a caller assert its
own connection properties. Host validation, which the broker had no need for,
is added here instead.

Usage:
    python web_status.py --status-path triage-state/daily-status.json \\
        --review-dir review/
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from wsgiref.simple_server import make_server

# The bind address is a constant, never configuration. A status page that can
# be published to 0.0.0.0 by passing a flag is a different piece of software
# with a different threat model: everything here assumes the only reachable
# clients are on this machine.
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# Rejecting everything else defends against DNS rebinding, where a hostile page
# resolves its own name to 127.0.0.1 and reaches this server from the owner's
# browser. Only these Host values are ours.
ALLOWED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "[::1]", "::1",
})

# Mirrors review_report.COUNT_KEYS, duplicated rather than imported to keep
# this module free of project imports. Unknown keys are ignored on render, so
# the two drifting apart degrades to showing less, never to showing something
# unreviewed.
COUNT_ORDER = (
    "scanned", "classified", "labeled", "drafted", "needs_review",
    "skipped", "failures", "deferred_draft_limit", "deferred_write_limit",
)

MAX_REPORTS = 25

# A readiness snapshot describes the moment it was taken. Past this age it is
# still shown - stale information beats a blank panel when you are debugging -
# but it is labelled, so nobody reads a week-old PASS as today's state.
READINESS_STALE_AFTER_HOURS = 24

# Mirrors connection_expiry, duplicated rather than imported to keep this
# module free of project imports. Unlike the count-key list, drift here would
# show a WRONG countdown rather than merely less information, so
# test_web_status pins these equal to the originals by importing both - a
# thing a test may do and this module may not.
TOKEN_LIFETIME_DAYS = 7
EXPIRING_SOON_DAYS = 2

MAX_DRAFTS = 100

# The complete set of fields that may ever be rendered for a draft. This is
# the whole of G5: a source document may carry anything at all - a subject, a
# body, a generated reply, a sender - and none of it can reach the page,
# because _draft_rows copies nothing that is not named here.
DRAFT_STATE_FIELDS = ("status", "thread_id", "draft_id")
DRAFT_REPORT_FIELDS = (
    "category", "confidence", "drafting_mode", "reason_codes",
    "draft_created", "draft_planned",
)

# Gmail ids are opaque and alphanumeric. Anything else is not put in a URL,
# even though the source is a local private file: a value that cannot be
# validated is a value that does not become a link.
GMAIL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# review_report.opaque_id truncates a sha256 hex digest. Reproduced here with
# hashlib rather than imported, so this module keeps zero project imports.
OPAQUE_ID_LENGTH = 16


def _opaque_id(value, length=OPAQUE_ID_LENGTH):
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:length]


def _gmail_url(account_index, thread_id=None):
    """A link to one thread, or to the Drafts folder when the id is unusable.

    The thread-id fragment is the usual Gmail shape but is not guaranteed to
    match the API threadId in every case, so the Drafts fallback exists and
    the raw id is always shown alongside for a manual search.
    """
    base = f"https://mail.google.com/mail/u/{int(account_index)}/"
    if thread_id and GMAIL_ID.match(str(thread_id)):
        return f"{base}#all/{thread_id}", True
    return f"{base}#drafts", False


def _read_json(path):
    """Return a parsed document, or None if it is absent or unreadable.

    Never raises: a malformed artifact should render as "unavailable" rather
    than take the page down, and the exception text could name a private path.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _counts(document):
    """Allowlisted, non-negative integer counts from a document."""
    raw = document.get("counts")
    raw = raw if isinstance(raw, dict) else {}
    counts = []
    for key in COUNT_ORDER:
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            continue
        counts.append((key, value))
    return counts


def _text(value, fallback="unknown"):
    """Escape a value for HTML, collapsing anything unexpected to a fallback."""
    if not isinstance(value, str) or not value.strip():
        return html.escape(fallback)
    return html.escape(value.strip()[:200])


class StatusSource:
    """Filesystem locations, resolved once at startup.

    Paths are fixed when the server is constructed and are never taken from a
    request. No route reads, joins, or otherwise derives a path from client
    input, so there is no traversal surface to defend.
    """

    def __init__(self, status_path, review_dir, readiness_path=None,
                 state_path=None, gmail_account_index=0,
                 connection_path=None):
        self.status_path = Path(status_path).expanduser().resolve()
        self.review_dir = Path(review_dir).expanduser().resolve()
        self.readiness_path = (
            Path(readiness_path).expanduser().resolve()
            if readiness_path else None
        )
        self.state_path = (
            Path(state_path).expanduser().resolve() if state_path else None
        )
        self.gmail_account_index = int(gmail_account_index)
        self.connection_path = (
            Path(connection_path).expanduser().resolve()
            if connection_path else None
        )

    def status(self):
        return _read_json(self.status_path)

    def readiness(self):
        if self.readiness_path is None:
            return None
        return _read_json(self.readiness_path)

    def connection(self):
        if self.connection_path is None:
            return None
        return _read_json(self.connection_path)

    def drafts(self):
        """Draft journal entries, joined to the newest report for context."""
        if self.state_path is None:
            return None
        state = _read_json(self.state_path)
        if state is None:
            return []
        newest = self.reports()
        report = newest[0][1] if newest else None
        return _draft_rows(state, report)

    def reports(self):
        """Most recent review reports, newest first."""
        try:
            candidates = sorted(
                (item for item in self.review_dir.glob("*.json")
                 if item.is_file()),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )[:MAX_REPORTS]
        except OSError:
            return []
        found = []
        for path in candidates:
            document = _read_json(path)
            if document is not None:
                found.append((path.name, document))
        return found


def _render_counts(counts):
    if not counts:
        return '<p class="empty">No counts recorded.</p>'
    cells = "".join(
        f'<div class="count"><span class="k">{html.escape(key)}</span>'
        f'<span class="v">{value}</span></div>'
        for key, value in counts
    )
    return f'<div class="counts">{cells}</div>'


def _render_status(document):
    if document is None:
        return (
            '<p class="empty">No run status available yet. It appears here '
            'after the first triage run writes its status file.</p>'
        )
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}
    outcome = run.get("outcome")
    tone = {
        "success": "ok", "failed": "bad", "running": "warn",
    }.get(outcome if isinstance(outcome, str) else "", "warn")

    codes = run.get("safe_error_codes")
    codes = [c for c in codes if isinstance(c, str)] if isinstance(codes, list) else []
    codes_html = (
        '<div class="codes">' + "".join(
            f'<span class="code">{html.escape(c)}</span>' for c in codes
        ) + "</div>"
        if codes else ""
    )

    return f"""
      <div class="rowline">
        <span class="pill {tone}">{_text(outcome)}</span>
        <span class="meta">mode <b>{_text(run.get("mode"))}</b></span>
        <span class="meta">started <b>{_text(run.get("started_at"), "-")}</b></span>
        <span class="meta">finished <b>{_text(run.get("finished_at"), "-")}</b></span>
        <span class="meta">lock held <b>{"yes" if run.get("lock_held") else "no"}</b></span>
      </div>
      {codes_html}
      {_render_counts(_counts(run))}
    """


def _parse_stamp(value):
    """An aware datetime from an ISO string, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        stamp = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.timezone.utc)


def _age_hours(created_at):
    """Hours since an ISO timestamp, or None if it cannot be read."""
    if not isinstance(created_at, str):
        return None
    try:
        stamp = dt.datetime.fromisoformat(created_at)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    delta = dt.datetime.now(dt.timezone.utc) - stamp
    return delta.total_seconds() / 3600.0


def _last_successful_run(status_document):
    """The finish time of the last run that actually succeeded, or None.

    Ground truth, as opposed to the countdown, which is only an estimate.
    """
    document = status_document if isinstance(status_document, dict) else {}
    run = document.get("last_run")
    run = run if isinstance(run, dict) else {}
    if run.get("outcome") != "success":
        return None
    finished = run.get("finished_at")
    return finished if isinstance(finished, str) and finished.strip() else None


def _connection_state(document, status_document, now=None):
    """Expected expiry for the connected account, with the evidence beside it.

    A prediction, never an observation: the seven days is Google's documented
    policy for a Testing-status external project applied to the moment the
    token was issued, and a grant can also be revoked earlier. So the last
    successful run is carried alongside and outranks the estimate - a run that
    succeeded after the predicted lapse proves the prediction wrong.
    """
    if document is None:
        return None
    now = now or dt.datetime.now(dt.timezone.utc)
    issued = _parse_stamp(document.get("last_authorized_at"))
    evidence = _parse_stamp(_last_successful_run(status_document))

    if issued is None:
        return {
            "account": document.get("account"),
            "state": "unknown", "tone": "warn",
            "summary": "Connection age unknown - reconnect to establish it",
            "expected_expiry": None, "last_successful_run": None,
            "connected_at": document.get("connected_at"),
        }

    expiry = issued + dt.timedelta(days=TOKEN_LIFETIME_DAYS)
    days = (expiry - now).total_seconds() / 86400.0
    overridden = bool(evidence is not None and evidence > expiry)

    if overridden:
        state, tone = "healthy", "ok"
        summary = ("Past the expected window, but a run succeeded since - "
                   "the estimate was wrong, not the connection")
    elif days < 0:
        state, tone = "expired", "bad"
        summary = "Connection expired - reconnect required"
    elif days < 1:
        state, tone = "expiring", "warn"
        summary = "Connection expected to expire in under a day"
    elif days <= EXPIRING_SOON_DAYS:
        state, tone = "expiring", "warn"
        summary = f"Connection expected to last {int(days)} more day" + \
            ("" if int(days) == 1 else "s")
    else:
        state, tone = "healthy", "ok"
        summary = f"Connection expected to last {int(days)} more days"

    return {
        "account": document.get("account"),
        "state": state, "tone": tone, "summary": summary,
        "expected_expiry": expiry.isoformat(timespec="seconds"),
        "last_successful_run": evidence.isoformat(timespec="seconds") if evidence else None,
        "connected_at": document.get("connected_at"),
    }


def _render_connection(state):
    if state is None:
        return (
            '<p class="empty">No account connected. Connecting one is a '
            'deliberate step taken at the terminal; this page only reports '
            'what it finds.</p>'
        )
    evidence = state.get("last_successful_run")
    evidence_html = (
        f'<span class="meta">last successful run <b>{_text(evidence)}</b></span>'
        if evidence
        else '<span class="meta">no successful run recorded yet</span>'
    )
    expiry_html = (
        f'<span class="meta">expected <b>{_text(state["expected_expiry"])}</b></span>'
        if state.get("expected_expiry") else ""
    )
    return f"""
      <div class="rowline">
        <span class="pill {state['tone']}">{_text(state['state'])}</span>
        <span class="meta">account <b>{_text(state.get('account'), '-')}</b></span>
        <span class="meta">connected <b>{_text(state.get('connected_at'), '-')}</b></span>
      </div>
      <p class="summary">{_text(state['summary'])}</p>
      <div class="rowline">
        {expiry_html}
        {evidence_html}
        <span class="est">estimate, not verified with Google</span>
      </div>
    """


def _render_readiness(document):
    if document is None:
        return (
            '<p class="empty">No readiness snapshot. Produce one with '
            '<code>check_readiness.py --json --json-output &lt;path&gt;</code> '
            'and point <code>--readiness-path</code> at it. It is not computed '
            'here: a readiness run takes tens of seconds and no page load '
            'should trigger that work.</p>'
        )

    ready = document.get("ready") is True
    scope = "live read-only" if document.get("live") else "offline"
    age = _age_hours(document.get("created_at"))
    stale = age is not None and age > READINESS_STALE_AFTER_HOURS

    if age is None:
        age_text = "age unknown"
    elif age < 1:
        age_text = "under an hour old"
    elif age < 48:
        age_text = f"{int(age)}h old"
    else:
        age_text = f"{int(age // 24)}d old"

    stale_badge = (
        f'<span class="pill warn">stale &middot; {html.escape(age_text)}</span>'
        if stale else f'<span class="meta">{html.escape(age_text)}</span>'
    )

    results = document.get("results")
    results = results if isinstance(results, list) else []
    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        ok = item.get("ok") is True
        required = item.get("required") is not False
        mark, tone = ("pass", "ok") if ok else (
            ("fail", "bad") if required else ("skip", "warn")
        )
        rows.append(
            f'<div class="chk"><span class="pill {tone}">{mark}</span>'
            f'<span class="cn">{_text(item.get("name"), "unnamed")}</span>'
            f'<span class="cd">{_text(item.get("detail"), "-")}</span></div>'
        )
    body = (
        f'<div class="checks">{"".join(rows)}</div>' if rows
        else '<p class="empty">The snapshot recorded no checks.</p>'
    )

    return f"""
      <div class="rowline">
        <span class="pill {"ok" if ready else "bad"}">{"ready" if ready else "not ready"}</span>
        <span class="meta">scope <b>{html.escape(scope)}</b></span>
        <span class="meta">account <b>{_text(document.get("account"), "-")}</b></span>
        {stale_badge}
      </div>
      {body}
    """


def _draft_rows(state_document, report_document, limit=MAX_DRAFTS):
    """Project state and report documents into a fixed, content-free shape.

    Only DRAFT_STATE_FIELDS and DRAFT_REPORT_FIELDS are copied, and the
    message id is hashed the way the review report already hashes it, so the
    raw id is used for joining and linking but never displayed.
    """
    messages = (state_document or {}).get("messages")
    messages = messages if isinstance(messages, dict) else {}

    by_opaque = {}
    items = (report_document or {}).get("messages")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                key = item.get("opaque_message_id")
                if isinstance(key, str):
                    by_opaque[key] = item

    rows = []
    for raw_id, record in list(messages.items())[:limit]:
        if not isinstance(raw_id, str) or not isinstance(record, dict):
            continue
        row = {"opaque_id": _opaque_id(raw_id)}
        for field in DRAFT_STATE_FIELDS:
            value = record.get(field)
            row[field] = value if isinstance(value, str) else ""
        context = by_opaque.get(row["opaque_id"], {})
        for field in DRAFT_REPORT_FIELDS:
            row[field] = context.get(field)
        labels = context.get("labels")
        names = labels.get("names") if isinstance(labels, dict) else None
        row["labels"] = [n for n in names if isinstance(n, str)] if isinstance(names, list) else []
        row["matched"] = bool(context)
        rows.append(row)
    return rows


def _render_drafts(rows, account_index):
    if not rows:
        return (
            '<p class="empty">No drafts recorded yet. They appear here once a '
            'run creates one and writes its journal entry.</p>'
        )
    blocks = []
    for row in rows:
        url, exact = _gmail_url(account_index, row.get("thread_id"))
        pending = row.get("status") == "draft_created"
        codes = row.get("reason_codes")
        codes = [c for c in codes if isinstance(c, str)] if isinstance(codes, list) else []
        codes_html = "".join(
            f'<span class="code neutral">{html.escape(c)}</span>' for c in codes
        )
        labels_html = "".join(
            f'<span class="lab">{html.escape(n)}</span>' for n in row.get("labels", [])
        )
        mode = row.get("drafting_mode")
        mode_html = (
            f'<span class="meta">via <b>{_text(mode)}</b></span>' if mode else ""
        )
        context_html = (
            f'<span class="meta">category <b>{_text(row.get("category"), "-")}</b></span>'
            f'<span class="meta">confidence <b>{_text(row.get("confidence"), "-")}</b></span>'
            f'{mode_html}'
            if row.get("matched")
            else '<span class="meta">no report context for this draft</span>'
        )
        link_note = "" if exact else ' <span class="meta">(folder \u2014 id below)</span>'
        blocks.append(f"""
          <article class="draft">
            <header>
              <span class="pill {"warn" if pending else "ok"}">{_text(row.get("status"), "unknown")}</span>
              {context_html}
              <a class="glink" href="{html.escape(url)}" target="_blank" rel="noopener noreferrer">open in Gmail</a>{link_note}
            </header>
            <div class="ids">
              <span>message <code>{html.escape(row["opaque_id"])}</code></span>
              <span>thread <code>{html.escape(str(row.get("thread_id") or "-"))}</code></span>
              <span>draft <code>{html.escape(str(row.get("draft_id") or "-"))}</code></span>
            </div>
            {f'<div class="codes">{codes_html}</div>' if codes_html else ""}
            {f'<div class="labs">{labels_html}</div>' if labels_html else ""}
          </article>
        """)
    return "".join(blocks)


def _render_reports(reports):
    if not reports:
        return (
            '<p class="empty">No review reports found. They appear here once a '
            'run is given <code>--review-report</code>.</p>'
        )
    blocks = []
    for name, document in reports:
        outcome = document.get("outcome")
        tone = "ok" if outcome == "success" else "bad"
        applied = "applied" if document.get("applied") else "dry run"
        messages = document.get("messages")
        count = len(messages) if isinstance(messages, list) else 0
        blocks.append(f"""
          <article class="report">
            <header>
              <span class="fname">{html.escape(name)}</span>
              <span class="pill {tone}">{_text(outcome)}</span>
              <span class="meta">{html.escape(applied)}</span>
              <span class="meta">mode <b>{_text(document.get("run_mode"))}</b></span>
              <span class="meta">{count} message(s)</span>
              <span class="meta">{_text(document.get("created_at"), "-")}</span>
            </header>
            {_render_counts(_counts(document))}
          </article>
        """)
    return "".join(blocks)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Triage status</title>
<style>
  :root {{
    --ground:#F5F8F8; --surface:#FFF; --ink:#0F1A1C; --soft:#4A5C5F;
    --faint:#7B8C8E; --rule:#D8E3E3; --accent:#0E5A61;
    --ok:#2E6B4F; --warn:#8A6410; --bad:#9B3B2F;
    --ok-bg:#E7F1EC; --warn-bg:#F6EEDC; --bad-bg:#F6E7E3;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --ground:#0C1416; --surface:#121F22; --ink:#E4EDEE; --soft:#A3B6B8;
      --faint:#77898B; --rule:#21353A; --accent:#5CBCC4;
      --ok:#6FC299; --warn:#D6A94A; --bad:#E08A78;
      --ok-bg:#12251E; --warn-bg:#2A2214; --bad-bg:#2B1A17;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--ground); color:var(--ink);
    font:15px/1.55 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
  .wrap {{ max-width:900px; margin:0 auto; padding:40px 22px 72px; }}
  h1 {{ font-size:1.5rem; margin:0 0 6px; letter-spacing:-0.01em; }}
  .sub {{ color:var(--soft); margin:0 0 8px; }}
  .scope {{ font:12px ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--faint); margin:0 0 34px; }}
  h2 {{ font-size:1rem; margin:36px 0 14px; padding-bottom:9px;
    border-bottom:1px solid var(--rule); }}
  .panel {{ background:var(--surface); border:1px solid var(--rule); padding:18px 20px; }}
  .rowline {{ display:flex; flex-wrap:wrap; gap:9px 18px; align-items:center; }}
  .pill {{ font:600 11.5px ui-monospace,SFMono-Regular,Menlo,monospace;
    letter-spacing:.05em; text-transform:uppercase; padding:3px 9px; border-radius:2px; }}
  .pill.ok {{ color:var(--ok); background:var(--ok-bg); }}
  .pill.bad {{ color:var(--bad); background:var(--bad-bg); }}
  .pill.warn {{ color:var(--warn); background:var(--warn-bg); }}
  .meta {{ font-size:13px; color:var(--soft); }}
  .meta b {{ color:var(--ink); font-weight:600; }}
  .counts {{ display:grid; gap:1px; background:var(--rule); border:1px solid var(--rule);
    grid-template-columns:repeat(auto-fill,minmax(132px,1fr)); margin-top:16px; }}
  .count {{ background:var(--surface); padding:9px 12px; display:flex;
    flex-direction:column; gap:2px; }}
  .count .k {{ font:11px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--faint); }}
  .count .v {{ font-size:17px; font-weight:600; font-variant-numeric:tabular-nums; }}
  .codes {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:13px; }}
  .code {{ font:11.5px ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--bad); background:var(--bad-bg); padding:3px 8px; border-radius:2px; }}
  .draft {{ background:var(--surface); border:1px solid var(--rule);
    padding:14px 18px; margin-bottom:10px; }}
  .draft header {{ display:flex; flex-wrap:wrap; gap:8px 16px; align-items:center; }}
  .glink {{ font:600 12.5px ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--accent); text-underline-offset:3px; }}
  .glink:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}
  .ids {{ display:flex; flex-wrap:wrap; gap:6px 18px; margin-top:10px;
    font-size:12px; color:var(--faint); }}
  .ids code {{ color:var(--soft); }}
  .code.neutral {{ color:var(--soft); background:var(--ground); }}
  .labs {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:9px; }}
  .lab {{ font:11.5px ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--accent); background:var(--ground); border:1px solid var(--rule);
    padding:2px 7px; border-radius:2px; }}
  .summary {{ margin:13px 0 11px; font-size:15px; font-weight:600; }}
  .est {{ font:11.5px ui-monospace,SFMono-Regular,Menlo,monospace;
    color:var(--faint); }}
  .checks {{ display:flex; flex-direction:column; gap:1px; background:var(--rule);
    border:1px solid var(--rule); margin-top:16px; }}
  .chk {{ background:var(--surface); padding:8px 12px; display:flex;
    gap:12px; align-items:baseline; flex-wrap:wrap; }}
  .chk .cn {{ font-weight:600; font-size:13.5px; min-width:190px; }}
  .chk .cd {{ font-size:13px; color:var(--soft); flex:1; min-width:200px; }}
  .report {{ background:var(--surface); border:1px solid var(--rule);
    padding:15px 18px; margin-bottom:10px; }}
  .report header {{ display:flex; flex-wrap:wrap; gap:8px 16px; align-items:center; }}
  .fname {{ font:600 12.5px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--accent); }}
  .empty {{ color:var(--faint); margin:0; }}
  code {{ font:0.87em ui-monospace,SFMono-Regular,Menlo,monospace; }}
  footer {{ margin-top:44px; padding-top:18px; border-top:1px solid var(--rule);
    font:12px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--faint); }}
</style></head>
<body><div class="wrap">
  <h1>Triage status</h1>
  <p class="sub">Read-only view of the last run and recent review reports.</p>
  <p class="scope">no writes &middot; no credentials &middot; no Gmail &middot; no Gemini &middot; {host}</p>
  <h2>Connection</h2>
  <div class="panel">{connection}</div>
  <h2>Readiness</h2>
  <div class="panel">{readiness}</div>
  <h2>Last run</h2>
  <div class="panel">{status}</div>
  <h2>Drafts</h2>
  {drafts}
  <h2>Review reports</h2>
  {reports}
  <footer>Serving {status_path}<br>Reports from {review_dir}<br>Readiness snapshot: {readiness_path}<br>Run journal: {state_path} &middot; message content is never shown here</footer>
</div></body></html>
"""


class StatusApp:
    """WSGI application. GET-only, exact-match routing, no client paths."""

    def __init__(self, source):
        self.source = source

    def __call__(self, environ, start_response):
        # GET first, before any work: this application has no state to change,
        # and refusing every other method makes that structural.
        if environ.get("REQUEST_METHOD", "GET") != "GET":
            return self._respond(
                start_response, "405 Method Not Allowed", "Method not allowed.",
            )

        if not self._host_allowed(environ):
            return self._respond(
                start_response, "400 Bad Request", "Unrecognized Host header.",
            )

        path = environ.get("PATH_INFO", "")
        if path == "/healthz":
            return self._respond(start_response, "200 OK", "ok")
        if path == "/":
            return self._page(start_response)
        return self._respond(start_response, "404 Not Found", "Not found.")

    @staticmethod
    def _host_allowed(environ):
        host = environ.get("HTTP_HOST", "")
        # A port is ours to serve on whatever it is; the name is what matters.
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return name.strip().lower() in ALLOWED_HOSTS

    def _connection_html(self):
        return _render_connection(_connection_state(
            self.source.connection(), self.source.status(),
        ))

    def _drafts_html(self):
        rows = self.source.drafts()
        if rows is None:
            return (
                '<p class="empty">Draft review is off. Point '
                '<code>--state-path</code> at the run journal to list drafts '
                'and link to them in Gmail. Message content is never shown '
                'here or stored locally; it stays in Gmail.</p>'
            )
        return _render_drafts(rows, self.source.gmail_account_index)

    def _page(self, start_response):
        body = PAGE.format(
            host=html.escape(f"{BIND_HOST}"),
            status=_render_status(self.source.status()),
            readiness=_render_readiness(self.source.readiness()),
            connection=self._connection_html(),
            drafts=self._drafts_html(),
            reports=_render_reports(self.source.reports()),
            status_path=html.escape(str(self.source.status_path)),
            review_dir=html.escape(str(self.source.review_dir)),
            readiness_path=html.escape(
                str(self.source.readiness_path) if self.source.readiness_path
                else "(not configured)"
            ),
            state_path=html.escape(
                str(self.source.state_path) if self.source.state_path
                else "(not configured)"
            ),
        ).encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"),
        ])
        return [body]

    @staticmethod
    def _respond(start_response, status, message):
        body = message.encode("utf-8")
        start_response(status, [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
        ])
        return [body]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only localhost status page for triage runs.",
    )
    parser.add_argument(
        "--status-path", default="triage-state/daily-status.json",
        help="PII-free run status JSON written by daily_triage.py",
    )
    parser.add_argument(
        "--review-dir", default="review",
        help="Directory holding PII-minimized review reports",
    )
    parser.add_argument(
        "--connection-path",
        help=("connection.json for the connected account. Shows who is "
              "connected and when the grant is expected to lapse."),
    )
    parser.add_argument(
        "--state-path",
        help=("Run journal (daily-state.json). Enables the draft list, which "
              "shows decisions and links to Gmail, never message content."),
    )
    parser.add_argument(
        "--gmail-account-index", type=int, default=0,
        help="Google account index for Gmail links (the u/N in the URL)",
    )
    parser.add_argument(
        "--readiness-path",
        help=("JSON snapshot written by check_readiness.py --json-output. "
              "Displayed, never produced here."),
    )
    # There is deliberately no --host. See BIND_HOST.
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Loopback port to listen on (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 0 <= args.gmail_account_index <= 99:
        parser.error("--gmail-account-index must be between 0 and 99")
    return args


def build_app(args):
    return StatusApp(StatusSource(
        args.status_path, args.review_dir, args.readiness_path,
        args.state_path, args.gmail_account_index, args.connection_path,
    ))


def main(argv=None):
    args = parse_args(argv)
    app = build_app(args)
    with make_server(BIND_HOST, args.port, app) as server:
        print(f"Status page on http://{BIND_HOST}:{args.port}/  (Ctrl-C to stop)")
        print("Read-only: no writes, no credentials, no Gmail or Gemini contact.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
