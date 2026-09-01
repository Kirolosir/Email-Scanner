"""Explicit, idempotent Gmail label bootstrap for the daily triage tool.

This is the only production module permitted to create Gmail labels.  It can
create only exact names from the reviewed JSON configuration; it never accepts
classifier output or an arbitrary label name on the command line.
"""
from __future__ import annotations

import argparse
import logging
import sys

from gmail_auth import get_gmail_service
from gmail_common import QuotaThrottle
from gmail_labeler import fetch_account_labels
from triage_config import DEFAULT_LABEL_CONFIG, load_triage_label_config


UNITS_LABELS_CREATE = 5
logger = logging.getLogger(__name__)


def plan_label_setup(account_labels, config):
    """Return an offline plan containing only reviewed configured names."""
    present = set(account_labels)
    return {
        "required_existing": [
            name for name in config.required_existing_names if name in present
        ],
        "required_missing": [
            name for name in config.required_existing_names if name not in present
        ],
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

    for name in plan["create"]:
        try:
            if throttle is not None:
                throttle.consume(UNITS_LABELS_CREATE)
            result = service.users().labels().create(
                userId="me", body=_label_body(name, config)
            ).execute()
            created.append((name, result.get("id", "")))
        except Exception as exc:
            failures.append((name, type(exc).__name__))
    return created, failures


def confirm(count):
    try:
        answer = input(
            f"\nCreate exactly {count} configured Gmail labels? "
            "Type 'yes' to proceed: "
        )
    except EOFError:
        return False
    return answer.strip().casefold() == "yes"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create only the reviewed Gmail triage labels missing from an account."
    )
    parser.add_argument(
        "--config", default=DEFAULT_LABEL_CONFIG,
        help=f"Reviewed label JSON (default: {DEFAULT_LABEL_CONFIG})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="List the exact setup plan without creating labels",
    )
    parser.add_argument(
        "--token-path",
        help="Separate Gmail token file (for example tokens/coach.json)",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Skip the typed confirmation (does not bypass configuration checks)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        config = load_triage_label_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"Invalid label configuration: {exc}")
        return 2

    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()
    account_labels = fetch_account_labels(service, throttle)
    plan = plan_label_setup(account_labels, config)

    print("Existing required campaign labels:")
    for name in plan["required_existing"]:
        print(f"  present: {name}")
    for name in plan["required_missing"]:
        print(f"  MISSING: {name} (setup will not create campaign labels)")

    print("\nConfigured triage labels:")
    for name in plan["already_present"]:
        print(f"  present: {name}")
    for name in plan["create"]:
        print(f"  create:  {name}")

    if plan["required_missing"]:
        print("\nBlocked: required existing campaign labels are missing.")
        return 2
    if args.dry_run:
        print("\nDry run - no labels created.")
        return 0
    if not plan["create"]:
        print("\nAll configured labels already exist; nothing changed.")
        return 0
    if not args.yes and not confirm(len(plan["create"])):
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
