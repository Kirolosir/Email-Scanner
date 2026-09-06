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
import html
import json
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

    def __init__(self, status_path, review_dir):
        self.status_path = Path(status_path).expanduser().resolve()
        self.review_dir = Path(review_dir).expanduser().resolve()

    def status(self):
        return _read_json(self.status_path)

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
  <h2>Last run</h2>
  <div class="panel">{status}</div>
  <h2>Review reports</h2>
  {reports}
  <footer>Serving {status_path}<br>Reports from {review_dir}</footer>
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

    def _page(self, start_response):
        body = PAGE.format(
            host=html.escape(f"{BIND_HOST}"),
            status=_render_status(self.source.status()),
            reports=_render_reports(self.source.reports()),
            status_path=html.escape(str(self.source.status_path)),
            review_dir=html.escape(str(self.source.review_dir)),
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
    # There is deliberately no --host. See BIND_HOST.
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Loopback port to listen on (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    return args


def build_app(args):
    return StatusApp(StatusSource(args.status_path, args.review_dir))


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
