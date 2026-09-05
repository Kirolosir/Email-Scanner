"""Read-only readiness command for one configured Gmail account.

Without ``--live`` this runs the complete offline test suite and validates
local, account-bound artifacts. ``--live`` additionally refreshes the
selected token in memory and reads only the Gmail profile and label list. It
never starts OAuth, calls Gemini, creates labels/drafts, or writes a token.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import readiness
from gmail_retry import gmail_execute


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Check local readiness by default; add --live for read-only Gmail "
            "identity and label checks. Never calls Gemini or writes Gmail."
        )
    )
    parser.add_argument("--account-config", required=True)
    parser.add_argument("--taxonomy-confirmation", required=True)
    parser.add_argument("--ai-drafting-approval")
    parser.add_argument("--template-approval")
    parser.add_argument("--templates", default="templates")
    parser.add_argument(
        "--token-path", default=os.environ.get("GMAIL_TOKEN_PATH", "token.json")
    )
    parser.add_argument(
        "--live", action="store_true",
        help=("Contact Gmail only to verify the token's account and list label "
              "names. Performs zero Gmail writes and never calls Gemini."),
    )
    parser.add_argument("--campaign-label")
    parser.add_argument("--campaign-approval")
    parser.add_argument("--campaign-body")
    parser.add_argument(
        "--broker-health-url",
        help=("Optional broker health endpoint; requires --live and contacts "
              "that URL without sending credentials"),
    )
    return parser.parse_args(argv)


def _pytest_check(arguments, description):
    project = Path(__file__).resolve().parent
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
        *arguments,
    ]
    result = subprocess.run(
        command, cwd=project, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    detail = lines[-1] if lines else f"{description} produced no output"
    if result.returncode:
        detail = f"exit {result.returncode}: {detail}"
    return result.returncode == 0, detail


def _build_read_only_gmail_service(token_path):
    """Load/refresh an existing token in memory without OAuth or persistence."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from gmail_auth import SCOPES

    credentials = Credentials.from_authorized_user_file(token_path, SCOPES)
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    if not credentials.valid:
        raise RuntimeError(
            "existing token is invalid and readiness will not start OAuth"
        )
    return build("gmail", "v1", credentials=credentials)


def _read_live_gmail_metadata(token_path):
    from gmail_common import QuotaThrottle, normalize_address
    from gmail_labeler import fetch_account_labels

    service = _build_read_only_gmail_service(token_path)
    account = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get(
            "emailAddress", ""
        )
    )
    labels = fetch_account_labels(service, QuotaThrottle())
    return account, labels


def _check_broker_health(url):
    if not url:
        return True, "not used for this readiness check"
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read(32).decode("utf-8", errors="replace").strip()
        if response.status != 200 or body != "ok":
            return False, f"unexpected health response ({response.status})"
    return True, "health endpoint returned 200 ok"


def _append_verification(report):
    report.results.append(readiness._guarded(
        "full offline test suite",
        lambda: _pytest_check((), "test suite"),
    ))
    report.results.append(readiness._guarded(
        "static no-send audit",
        lambda: _pytest_check(("test_no_send_operations.py",),
                              "no-send audit"),
    ))


def _report_for(args, account, labels, live):
    report = readiness.build_report(
        args.account_config,
        args.taxonomy_confirmation,
        args.ai_drafting_approval,
        args.templates,
        args.template_approval,
        account,
        labels,
        live=live,
        token_path=args.token_path,
        campaign_approval_path=args.campaign_approval,
        campaign_label=args.campaign_label,
        campaign_body_path=args.campaign_body,
    )
    _append_verification(report)
    return report


def main(argv=None):
    args = parse_args(argv)
    if args.broker_health_url and not args.live:
        print("--broker-health-url requires --live because it contacts Render.")
        return 2

    try:
        profile = readiness.load_profile(args.account_config)
        declared_account = profile.account
    except Exception:  # noqa: BLE001 - rendered by the guarded config check
        declared_account = ""

    local_report = _report_for(
        args, declared_account, labels=None, live=False
    )
    if not args.live or not local_report.ready:
        print(local_report.render())
        if args.live and not local_report.ready:
            print("\nGmail was not contacted because local readiness failed.")
        return 0 if local_report.ready else 1

    print(
        "Local checks passed. Performing read-only Gmail profile and label "
        "checks; no messages, drafts, or bodies will be read."
    )
    try:
        account, labels = _read_live_gmail_metadata(args.token_path)
    except Exception as exc:  # noqa: BLE001 - fail closed
        print(f"Could not complete live Gmail checks ({type(exc).__name__}: {exc})")
        print("Status: NOT READY")
        return 2

    live_report = _report_for(args, account, labels, live=True)
    live_report.results.append(readiness._guarded(
        "OAuth broker health",
        lambda: _check_broker_health(args.broker_health_url),
    ))
    print(live_report.render())
    return 0 if live_report.ready else 1


if __name__ == "__main__":
    sys.exit(main())
