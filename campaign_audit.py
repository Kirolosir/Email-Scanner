"""Read-only, private recipient audit for protected Gmail campaigns.

This command may read Gmail and call Gemini, but it has no Gmail mutation
operation. Its report contains recipient addresses for human review, never
message bodies, subjects, credentials, tokens, or free-form model reasoning.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import account_profile as _PROFILE_MOD
from account_profile import load_profile as _load_profile
from campaign import (
    canonical_address,
    fetch_metadata,
    list_all_message_ids,
    load_aliases,
)
from gemini_client import classify
from gmail_auth import get_gmail_service
from gmail_common import QuotaThrottle, normalize_address
from gmail_labeler import fetch_account_labels
from message_safety import DEFAULT_MAX_BODY_CHARS, opaque_id, validate_max_body_chars
from private_runtime import atomic_write_json
from triage import fetch_messages, message_to_email, plan_message
from gmail_retry import gmail_execute


REPORT_VERSION = 1
_PROFILE = _load_profile()

RECRUIT_CATEGORIES = set(_PROFILE.evidence_categories)
# Categories audited as non-recruit correspondence.
NON_RECRUIT_AUDIT_CATEGORIES = frozenset(_PROFILE.non_recruit_audit_categories)
# The year the evidence gate requires model and message text to agree on.
_EXPECTED_YEAR = _PROFILE.evidence_expected_value


def dedupe_for_audit(records, aliases=None):
    """Keep the newest metadata record for each explicit canonical target."""
    result = {}
    for record in records:
        address = record.get("reply_address") or record.get("sender", "")
        canonical = canonical_address(address, aliases) if address else ""
        key = canonical or f"invalid:{opaque_id(record.get('message_id'))}"
        current = result.get(key)
        if current is None or record.get("internal_date", 0) > current.get(
            "internal_date", 0
        ):
            result[key] = record
    return result


def audit_entry(record, plan=None, aliases=None):
    """Create a body-free, fixed-schema human review record."""
    delivery = record.get("delivery_safety", {})
    recipient = record.get("reply_address") or record.get("sender", "")
    canonical = canonical_address(recipient, aliases) if recipient else ""
    reason_codes = list(delivery.get("reason_codes", []))
    recommendation = "review"
    category = sender_type = confidence = grad_year = local_grad_year = "unknown"
    evidence_codes = []
    model_used = False

    if delivery.get("status") == "automated":
        recommendation = "exclude"
        reason_codes.append("automated_message")
        category = _PROFILE_MOD.SYSTEM_CATEGORY_ADMINISTRATIVE
        sender_type = _PROFILE_MOD.SYSTEM_CATEGORY_ADMINISTRATIVE
        confidence = "high"
    elif delivery.get("status") != "normal" or not canonical:
        recommendation = "exclude"
        reason_codes.append("unsafe_recipient_metadata")
    elif plan is not None:
        classification = plan["classification"]
        model_used = plan.get("classification_called", False)
        category = plan["category"]
        sender_type = plan["sender_type"]
        confidence = plan.get("confidence", "unknown")
        grad_year = plan["grad_year"]
        local_grad_year = classification.get("local_grad_year", "unknown")
        evidence_codes = list(classification.get("local_evidence_codes", []))
        if (
            classification.get("actionable") is True
            and category in RECRUIT_CATEGORIES
            and sender_type in _PROFILE.evidence_sender_types
            and confidence == "high"
            and grad_year == local_grad_year == _EXPECTED_YEAR
        ):
            recommendation = "candidate_for_human_approval"
            reason_codes.append(f"verified_{_EXPECTED_YEAR}_recruit_candidate")
        elif category in NON_RECRUIT_AUDIT_CATEGORIES:
            recommendation = "exclude"
            reason_codes.append("non_recruit_sender_type")
        else:
            reason_codes.append("classification_requires_human_review")

    return {
        "recipient": canonical,
        "message_key": opaque_id(record.get("message_id")),
        "recommendation": recommendation,
        "reason_codes": sorted(set(reason_codes)),
        "deterministic": {
            "delivery_status": delivery.get("status", "ambiguous"),
            "local_grad_year": local_grad_year,
            "year_evidence_codes": sorted(set(evidence_codes)),
        },
        "model": {
            "used": bool(model_used),
            "category": category,
            "sender_type": sender_type,
            "confidence": confidence,
            "grad_year": grad_year,
        },
    }


def build_report(account, label, entries):
    summary = {
        "total": len(entries),
        "candidate_for_human_approval": sum(
            item["recommendation"] == "candidate_for_human_approval"
            for item in entries
        ),
        "review": sum(item["recommendation"] == "review" for item in entries),
        "exclude": sum(item["recommendation"] == "exclude" for item in entries),
    }
    return {
        "version": REPORT_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "account": normalize_address(account),
        "label": label,
        "notice": (
            "Private read-only review artifact. Recommendations are not approval; "
            "a coach-reviewed campaign approval file must be created separately."
        ),
        "summary": summary,
        "entries": entries,
    }


def write_report(path, report):
    target = Path(path)
    if target.exists():
        raise FileExistsError(
            f"audit report already exists: {target}; choose a new path"
        )
    atomic_write_json(target, report)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Read-only recipient audit; may read Gmail/call Gemini, never writes Gmail"
        )
    )
    parser.add_argument("label", help="Exact existing Gmail campaign label")
    parser.add_argument("--output", required=True, help="New private JSON report path")
    parser.add_argument("--token-path", help="Separate Gmail token file")
    parser.add_argument("--aliases", help="Explicit alias,canonical mapping")
    parser.add_argument("--max-scan", type=int)
    parser.add_argument("--limit", type=int, help="Audit at most N unique recipients")
    parser.add_argument("--max-body-chars", type=int, default=DEFAULT_MAX_BODY_CHARS)
    parser.add_argument("--quiet", action="store_true", help="Print counts only")
    args = parser.parse_args(argv)
    for name in ("max_scan", "limit"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error(f"--{name.replace('_', '-')} must be greater than zero")
    try:
        validate_max_body_chars(args.max_body_chars)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv=None, classifier=None):
    args = parse_args(argv)
    classifier = classifier or classify
    try:
        aliases = load_aliases(args.aliases)
    except (OSError, ValueError) as exc:
        print(f"Audit configuration error: {exc}")
        return 2
    if Path(args.output).exists():
        print("Audit output already exists; choose a new path. Nothing contacted.")
        return 2

    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()
    account = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get("emailAddress", "")
    )
    # A read validates that label resolution will use the current account.
    fetch_account_labels(service, throttle)
    message_ids = list_all_message_ids(
        service, args.label, throttle, max_scan=args.max_scan,
        progress=not args.quiet,
    )
    records, metadata_failures = fetch_metadata(
        service, message_ids, throttle, own_address=account,
        progress=not args.quiet,
    )
    selected = list(dedupe_for_audit(records, aliases).values())
    selected.sort(key=lambda item: item.get("internal_date", 0), reverse=True)
    if args.limit is not None:
        selected = selected[:args.limit]

    entries = []
    full_ids = [
        record["message_id"] for record in selected
        if record.get("delivery_safety", {}).get("status") == "normal"
    ]
    full_messages, body_failures = fetch_messages(service, full_ids, throttle)
    full_by_id = {message["id"]: message for message in full_messages}
    for record in selected:
        plan = None
        message = full_by_id.get(record["message_id"])
        if message is not None:
            email = message_to_email(
                message, max_body_chars=args.max_body_chars,
                own_address=account,
            )
            email["message_id"] = message["id"]
            plan = plan_message(
                email, {}, {}, {}, no_label=True, classifier=classifier
            )
        entries.append(audit_entry(record, plan=plan, aliases=aliases))

    report = build_report(account, args.label, entries)
    report["summary"]["metadata_fetch_failures"] = len(metadata_failures)
    report["summary"]["body_fetch_failures"] = len(body_failures)
    try:
        write_report(args.output, report)
    except OSError as exc:
        print(f"Could not write private audit report ({type(exc).__name__}).")
        return 2

    print("Read-only audit complete; Gmail writes: 0; drafts created: 0")
    print(f"  messages scanned: {len(message_ids)}")
    print(f"  unique reviewed:  {len(entries)}")
    print(f"  approval candidates: {report['summary']['candidate_for_human_approval']}")
    print(f"  manual review:       {report['summary']['review']}")
    print(f"  excluded:            {report['summary']['exclude']}")
    print(f"Private report: {args.output}")
    print("This report is not an approval. Coach review is still required.")
    return 1 if metadata_failures or body_failures else 0


if __name__ == "__main__":
    sys.exit(main())
