"""Explicit, idempotent Gmail label bootstrap for the daily triage tool.

This is the only production module permitted to create Gmail labels.  It can
create only exact names from the reviewed JSON configuration; it never accepts
classifier output or an arbitrary label name on the command line.
"""
from __future__ import annotations

import argparse
import logging
import sys

from account_profile import assert_profile_matches_account, load_profile
from gmail_auth import get_gmail_service
from gmail_common import QuotaThrottle, normalize_address
from gmail_labeler import fetch_account_labels
from triage_config import DEFAULT_LABEL_CONFIG, load_triage_label_config
from taxonomy import validate_label_name
from gmail_retry import gmail_execute


UNITS_LABELS_CREATE = 5
MAX_LABEL_CREATES = 100
logger = logging.getLogger(__name__)


def plan_label_setup(account_labels, config):
    """Return an offline plan containing only reviewed configured names."""
    present = set(account_labels)
    present_folded = {name.casefold(): name for name in present}
    for name in config.all_names:
        validate_label_name(name)
        collision = present_folded.get(name.casefold())
        if collision is not None and collision != name:
            raise ValueError(
                f"configured label {name!r} conflicts with existing label "
                f"{collision!r}; exact spelling is required"
            )
    return {
        "already_present": [
            name for name in config.creatable_names if name in present
        ],
        "create": [
            name for name in config.creatable_names if name not in present
        ],
    }


def _label_body(name, config):
    body = {"name": name}
    if name == config.system["processed"]:
        body.update({
            "labelListVisibility": "labelHide",
            "messageListVisibility": "hide",
        })
    return body


def apply_label_setup(service, config, plan, throttle=None, dry_run=False):
    """Create missing configured labels, isolating per-label failures."""
    created = []
    failures = []
    if dry_run:
        return created, failures

    reviewed = set(config.all_names)
    requested = list(plan.get("create", ()))
    if len(requested) > MAX_LABEL_CREATES:
        raise ValueError(
            f"label setup is bounded to {MAX_LABEL_CREATES} creations"
        )
    if len(requested) != len(set(requested)) or not set(requested) <= reviewed:
        raise ValueError("label setup plan contains an unreviewed label name")

    for name in requested:
        try:
            if throttle is not None:
                throttle.consume(UNITS_LABELS_CREATE)
            result = gmail_execute(service.users().labels().create(
                userId="me", body=_label_body(name, config)
            ))
            created.append((name, result.get("id", "")))
        except Exception as exc:
            failures.append((name, type(exc).__name__))
    return created, failures


def confirmation_phrase(account, configured_count, create_count):
    return (
        f"I approve the complete set of {configured_count} configured Gmail "
        f"labels for {account} and creation of exactly {create_count} missing "
        "labels"
    )


def confirm(account, configured_count, create_count, reader=input):
    expected = confirmation_phrase(account, configured_count, create_count)
    print("\nTo create this complete reviewed label set, type exactly:")
    print(expected)
    try:
        answer = reader("\n> ")
    except EOFError:
        return False
    return answer.strip() == expected


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create only the reviewed Gmail triage labels missing from an account."
    )
    parser.add_argument(
        "--config",
        help=("Reviewed label JSON. Omit with --account-config to use its "
              f"embedded labels; legacy default is {DEFAULT_LABEL_CONFIG}"),
    )
    parser.add_argument(
        "--account-config", metavar="FILE",
        help="Per-account taxonomy, label, and drafting configuration",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview only; with --live, read existing Gmail label names",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Contact Gmail read-only to compare configured and existing labels",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Contact Gmail and create the confirmed missing configured labels",
    )
    parser.add_argument(
        "--token-path",
        help="Separate Gmail token file (for example tokens/coach.json)",
    )
    return parser.parse_args(argv)


def main(argv=None, reader=input):
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        profile = load_profile(args.account_config)
        config = load_triage_label_config(args.config, profile=profile)
    except (OSError, ValueError) as exc:
        print(f"Invalid label configuration: {exc}")
        return 2

    if args.apply and args.dry_run:
        print("Invalid options: --apply and --dry-run cannot be combined.")
        return 2
    if args.apply and not args.live:
        print("Invalid options: --apply also requires explicit --live.")
        return 2

    print(f"Account: {profile.account or '(legacy profile; verified only live)'}")
    print("Configured Gmail labels:")
    for name in config.all_names:
        print(f"  {name}")

    # Offline is the default. Merely previewing reviewed configuration must
    # never initialize OAuth, refresh a token, or inspect the mailbox.
    if not args.live:
        print("\nOffline preview - Gmail was not contacted and nothing changed.")
        return 0

    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()
    own_address = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get("emailAddress", "")
    )
    try:
        assert_profile_matches_account(profile, own_address)
    except ValueError as exc:
        print(f"Account config error: {exc}")
        return 2
    account_labels = fetch_account_labels(service, throttle)
    try:
        plan = plan_label_setup(account_labels, config)
    except ValueError as exc:
        print(f"Label setup blocked: {exc}")
        return 2

    print("\nLive label comparison:")
    for name in plan["already_present"]:
        print(f"  present: {name}")
    for name in plan["create"]:
        print(f"  create:  {name}")

    if not args.apply:
        print("\nLive read-only preview - no labels created.")
        return 0
    if not plan["create"]:
        print("\nAll configured labels already exist; nothing changed.")
        return 0
    if not confirm(
        own_address, len(config.all_names), len(plan["create"]), reader=reader
    ):
        print("Aborted; no labels created.")
        return 1

    created, failures = apply_label_setup(
        service, config, plan, throttle=throttle, dry_run=False
    )
    for name, _label_id in created:
        print(f"  created: {name}")
    for name, error_type in failures:
        print(f"  ERROR: {name} ({error_type})")
    print(f"\nCreated {len(created)} labels; {len(failures)} failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
