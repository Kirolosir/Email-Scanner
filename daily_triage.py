"""Once-daily, idempotent Gmail inbox triage and reply-draft preparation.

The default invocation is a dry run.  Live use requires ``--apply`` plus the
existing confirmation gate.  This module never sends email and never creates
labels; setup_labels.py is the sole explicit label-creation entry point.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

from campaign import DraftLog, new_log_path
from account_profile import load_profile as _load_profile
from account_profile import assert_profile_matches_account
from account_profile import load_profile as _load_account_profile
from drafting import (
    MODE_GENERIC,
    load_ai_drafting_approval,
    precheck_ai_drafting_approval,
)
from gmail_auth import get_gmail_service
from taxonomy import load_taxonomy_confirmation
from gmail_retry import gmail_execute

_PROFILE = _load_profile()
from gmail_common import (
    LIST_PAGE_SIZE,
    UNITS_DRAFTS_CREATE,
    UNITS_DRAFTS_GET,
    UNITS_DRAFTS_LIST,
    QuotaThrottle,
    build_draft_body,
    list_message_ids_by_query,
    normalize_address,
)
from gmail_labeler import apply_labels, build_label_index, fetch_account_labels
from triage import (
    DEFAULT_TEMPLATE_DIR,
    attach_label_names,
    build_template_approvals,
    precheck_template_approval,
    fetch_message_metadata,
    fetch_messages,
    load_templates,
    message_to_email,
    parse_approved_names,
    plan_message,
    print_notes,
    print_plan_table,
    SAFETY_HEADERS,
)
from triage_config import DEFAULT_LABEL_CONFIG, load_triage_label_config
from gemini_client import THROTTLE_SECONDS
from gmail_reader import get_header_values
from message_safety import (
    DEFAULT_MAX_BODY_CHARS,
    assess_delivery_headers,
    opaque_id,
    validate_max_body_chars,
)
from private_runtime import (
    LOCKED_EXIT_CODE,
    AlreadyRunningError,
    ExclusiveRunLock,
    RunStatus,
    ensure_private_directory,
)


DEFAULT_STATE_PATH = _PROFILE.state_path
DEFAULT_STATUS_PATH = _PROFILE.status_path
DEFAULT_LOCK_DIR = _PROFILE.lock_dir
LOCAL_TIMEZONE = ZoneInfo(_PROFILE.timezone)
logger = logging.getLogger(__name__)


def build_initial_query(lookback_months=2):
    if not isinstance(lookback_months, int) or lookback_months <= 0:
        raise ValueError("lookback_months must be a positive integer")
    return (
        f"newer_than:{lookback_months}m "
        "-in:spam -in:trash -in:sent -in:drafts"
    )


def build_daily_query(overlap_days=3):
    if not isinstance(overlap_days, int) or overlap_days <= 0:
        raise ValueError("overlap_days must be a positive integer")
    return (
        f"newer_than:{overlap_days}d "
        "-in:spam -in:trash -in:sent -in:drafts"
    )


class DailyState:
    """Small private journal written atomically after every draft transition."""

    VERSION = 1
    ALLOWED_STATUSES = {"draft_created", "complete"}

    def __init__(self, path=DEFAULT_STATE_PATH):
        self.path = Path(path)
        self.data = {
            "version": self.VERSION,
            "last_daily_date": None,
            "messages": {},
        }

    def load(self, restrict_permissions=True):
        if not self.path.exists():
            return self
        try:
            with self.path.open(encoding="utf-8") as state_file:
                candidate = json.load(state_file)
            self._validate(candidate)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(
                f"daily state is invalid ({type(exc).__name__}); refusing to reset it"
            ) from exc
        self.data = candidate
        if restrict_permissions:
            self._restrict_existing_permissions()
        return self

    def _validate(self, candidate):
        if not isinstance(candidate, dict) or candidate.get("version") != self.VERSION:
            raise ValueError("unsupported state schema")
        if candidate.get("last_daily_date") is not None:
            if not isinstance(candidate["last_daily_date"], str):
                raise ValueError("last_daily_date must be an ISO date string")
            dt.date.fromisoformat(candidate["last_daily_date"])
        messages = candidate.get("messages")
        if not isinstance(messages, dict):
            raise ValueError("state messages must be an object")
        for message_id, record in messages.items():
            if not isinstance(message_id, str) or not isinstance(record, dict):
                raise ValueError("malformed message state")
            if record.get("status") not in self.ALLOWED_STATUSES:
                raise ValueError("unsupported message status")
            for key in ("thread_id", "draft_id"):
                if key in record and not isinstance(record[key], str):
                    raise ValueError(f"message state {key} must be a string")

    def _restrict_existing_permissions(self):
        try:
            os.chmod(self.path, 0o600)
            os.chmod(self.path.parent, 0o700)
        except OSError:
            logger.warning("Could not enforce private daily-state permissions")

    def save(self):
        # ensure_private_directory, not a bare mkdir: mkdir's mode covers only
        # the leaf, so a nested state_dir left its parent world-listable.
        try:
            ensure_private_directory(self.path.parent)
        except OSError:
            logger.warning("Could not enforce 0700 on daily-state directory")

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as state_file:
                json.dump(self.data, state_file, sort_keys=True, separators=(",", ":"))
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(temporary, self.path)
            self._restrict_existing_permissions()
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def record_for(self, message_id):
        return self.data["messages"].get(message_id, {})

    def record_draft(self, message_id, thread_id, draft_id):
        self.data["messages"][message_id] = {
            "status": "draft_created",
            "thread_id": thread_id,
            "draft_id": draft_id,
        }
        self.save()

    def record_complete(self, message_id, thread_id, draft_id=""):
        self.data["messages"][message_id] = {
            "status": "complete",
            "thread_id": thread_id,
            "draft_id": draft_id,
        }
        self.save()

    def mark_daily_complete(self, local_date):
        self.data["last_daily_date"] = local_date.isoformat()
        self.save()

    def already_ran_today(self, local_date):
        return self.data.get("last_daily_date") == local_date.isoformat()


def validate_required_labels(account_labels, config):
    return [name for name in config.all_names if name not in account_labels]


def render_draft_preview(plans, scheduled=False):
    """Render the wording of every draft this run would create.

    The point of a dry run is deciding whether to authorize real drafts, and
    that decision cannot be made from a "Draft: yes" column. Before this, a
    dry run reported that drafts would be created without ever showing what
    they would say.

    Suppressed in --scheduled runs: unattended output stays free of subjects
    and message-derived text.

    Returns the rendered text, or "" when there is nothing to show.
    """
    if scheduled:
        return ""
    drafting = [plan for plan in plans if plan.get("template")]
    if not drafting:
        return ""

    lines = ["", "=" * 72,
             f"DRAFT PREVIEW - wording of all {len(drafting)} draft(s) this "
             "run would create", "=" * 72]
    for index, plan in enumerate(drafting, start=1):
        email = plan.get("email", {})
        source = plan.get("draft_source") or "template"
        lines.append("")
        lines.append(f"[{index}] category: {plan.get('category', 'unknown')}"
                     f"   source: {source}")
        lines.append(f"    in reply to: {email.get('subject', '(no subject)')}")
        lines.append(f"    to: {email.get('reply_address') or email.get('from', '')}")
        lines.append("    " + "-" * 64)
        for line in (plan["template"] or "").splitlines() or [""]:
            lines.append(f"    {line}")
        lines.append("    " + "-" * 64)
    lines.append("")
    lines.append("Review the wording above before authorizing a real run.")
    return "\n".join(lines)


def select_candidates(messages, limit, already_processed):
    """Choose which fetched messages this run will process.

    ``limit`` is a budget of Gmail WRITE operations, and every message this
    run touches costs at least one of them - the processed label - so at most
    ``limit`` messages can be admitted here. The exact per-plan cost is not
    known until the plan exists; plans_within_write_budget enforces the real
    bound afterwards. This is the cheap upper bound that stops the run
    fetching and classifying messages it could never afford to write.

    Module-level and directly testable on purpose: this is one of the places
    a run decides what --limit means, and when two such places disagreed the
    budget leaked. Testing them only in isolation cannot catch that.

    Returns (candidates, skipped_count).
    """
    candidates = []
    skipped = 0
    for message in messages:
        if already_processed(message):
            skipped += 1
            continue
        candidates.append(message)
        if limit is not None and len(candidates) >= limit:
            break
    return candidates, skipped


def plan_write_cost(plan):
    """Gmail write operations one plan performs: label adds plus a draft.

    An upper bound. A plan whose draft already exists in the journal, or
    whose labels fail, performs fewer writes; it never performs more.
    """
    return (
        len(plan["decision"].add)
        + 1                                        # the processed label
        + (1 if plan.get("template") is not None else 0)
    )


def plans_within_write_budget(plans, limit):
    """Split plans into those this run can afford and those it defers.

    ``--limit N`` means at most N Gmail writes in total - label adds plus
    drafts - not N messages and not N classifications. A measured
    ``--limit 15`` run previously wrote up to 182 labels across 158
    messages, because the limit bounded classification only.

    Admission is by whole plan. Stopping midway through one would leave a
    message carrying its category label but not the processed label, so the
    next run would treat it as new work. Deferred plans are simply not
    marked processed, so the following run picks them up: the limit becomes
    a throttle on a staged rollout rather than a way to skip mail.

    Returns (admitted, deferred).
    """
    if limit is None:
        return list(plans), []
    admitted = []
    spent = 0
    for index, plan in enumerate(plans):
        cost = plan_write_cost(plan)
        if spent + cost > limit:
            return admitted, list(plans[index:])
        admitted.append(plan)
        spent += cost
    return admitted, []


def add_daily_review_policy(plan, config):
    """Route every unsafe/no-draft outcome to the reviewed review label."""
    if plan.get("suppression_code") == "automated_message":
        # Deterministically identified automated mail is a safe terminal case:
        # category it as Administrative and never draft or call Gemini.
        plan["needs_review"] = False
        plan["review_reasons"] = []
        return plan
    review_reasons = []
    if plan["category"] == "unknown" or plan["sender_type"] == "unknown":
        review_reasons.append("classification is unknown or sender is ambiguous")
    if plan["classification_error"]:
        review_reasons.append("classification failed")
    if plan["classification"].get("valid") is False:
        review_reasons.append("classification structure was invalid")
    if plan["decision"].conflicts:
        review_reasons.append("existing labels conflict with classification")
    if plan["draft_skip"]:
        review_reasons.append(plan["draft_skip"])

    review_name = config.system["needs_review"]
    current = set(plan["email"].get("label_names", []))
    if review_reasons and review_name not in current:
        if review_name not in plan["decision"].add:
            plan["decision"].add.append(review_name)
    plan["needs_review"] = bool(review_reasons)
    plan["review_reasons"] = review_reasons
    return plan


def reconcile_existing_drafts(plans, state, draft_threads, config):
    """Block external/manual or missing program-owned drafts before writes."""
    review_name = config.system["needs_review"]
    for plan in plans:
        email = plan["email"]
        record = state.record_for(email["message_id"])
        existing_id = draft_threads.get(email["thread_id"], "")
        recorded_id = record.get("draft_id", "")
        recorded_status = record.get("status")
        external = bool(existing_id and not (
            recorded_status in {"draft_created", "complete"}
            and recorded_id == existing_id
        ))
        missing_owned = bool(
            recorded_status == "draft_created" and recorded_id and not existing_id
        )
        if not (external or missing_owned):
            continue
        plan["template"] = None
        plan["template_key"] = None
        plan["existing_manual_draft"] = external
        plan["missing_owned_draft"] = missing_owned
        plan["draft_skip"] = (
            "existing manual/external draft requires review; not drafting"
            if external else
            "program-recorded draft is missing; requires review; not drafting"
        )
        if review_name not in email.get("label_names", []):
            if review_name not in plan["decision"].add:
                plan["decision"].add.append(review_name)
        plan["needs_review"] = True
        plan.setdefault("review_reasons", []).append(plan["draft_skip"])
    return plans


def list_existing_draft_threads(service, throttle):
    """Return {thread_id: draft_id}, paginating without reading draft bodies."""
    threads = {}
    page_token = None
    while True:
        throttle.consume(UNITS_DRAFTS_LIST)
        response = gmail_execute(service.users().drafts().list(
            userId="me", maxResults=LIST_PAGE_SIZE, pageToken=page_token
        ))
        for draft in response.get("drafts", []):
            message = draft.get("message", {})
            thread_id = message.get("threadId")
            if not thread_id:
                throttle.consume(UNITS_DRAFTS_GET)
                detail = gmail_execute(service.users().drafts().get(
                    userId="me", id=draft["id"], format="minimal"
                ))
                thread_id = detail.get("message", {}).get("threadId")
            if thread_id:
                threads.setdefault(thread_id, draft["id"])
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return threads


def _create_reply_draft(service, plan, throttle):
    email = plan["email"]
    record = {
        "sender": email["from"],
        "reply_address": email.get("reply_address", email["from"]),
        "subject": email["subject"],
        "rfc_message_id": email["rfc_message_id"],
        "thread_id": email["thread_id"],
    }
    throttle.consume(UNITS_DRAFTS_CREATE)
    return gmail_execute(service.users().drafts().create(
        userId="me", body=build_draft_body(record, plan["template"])
    ))


def execute_daily_plan(service, plan, account_labels, throttle, draft_log,
                       state, draft_threads):
    """Execute one plan with restart-safe draft and processed transitions."""
    email = plan["email"]
    message_id = email["message_id"]
    thread_id = email["thread_id"]
    errors = []
    added = []
    draft_id = ""

    try:
        if plan["decision"].add:
            apply_labels(
                service, message_id, plan["decision"].add,
                account_labels, throttle,
            )
            added.extend(plan["decision"].add)
    except Exception as exc:
        errors.append(f"labels failed ({type(exc).__name__})")

    if plan["template"] is not None:
        record = state.record_for(message_id)
        if record.get("status") in {"draft_created", "complete"}:
            draft_id = record.get("draft_id", "")
        elif thread_id in draft_threads:
            # A thread draft not present in our journal belongs to a person or
            # another tool. It is never adopted or placed in our rollback log.
            return added, "", ["existing_manual_draft"]
        else:
            try:
                result = _create_reply_draft(service, plan, throttle)
                draft_id = result["id"]
                draft_log.record(draft_id)
                # Persist before any later API call. A restart sees this state
                # and cannot create a second draft for the source message.
                state.record_draft(message_id, thread_id, draft_id)
                draft_threads[thread_id] = draft_id
            except Exception as exc:
                errors.append(f"draft failed ({type(exc).__name__})")

    if errors:
        return added, draft_id, errors

    try:
        apply_labels(
            service, message_id, [plan["processed_label"]],
            account_labels, throttle,
        )
        added.append(plan["processed_label"])
    except Exception as exc:
        return added, draft_id, [f"processed label failed ({type(exc).__name__})"]

    state.record_complete(message_id, thread_id, draft_id)
    return added, draft_id, []


def confirm(label_count, draft_count):
    try:
        answer = input(
            f"\nApply up to {label_count} labels and prepare {draft_count} drafts? "
            "Type 'yes' to proceed: "
        )
    except EOFError:
        return False
    return answer.strip().casefold() == "yes"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Daily inbox classification, add-only labels, and unsent drafts."
    )
    parser.add_argument(
        "mode", nargs="?", choices=("initial", "daily"), default="initial",
        help="initial two-month backfill or overlapping daily scan (default: initial)",
    )
    parser.add_argument(
        "--config",
        help=("Reviewed label JSON. Omit with --account-config to use labels "
              "embedded in that account profile; legacy default is "
              f"{DEFAULT_LABEL_CONFIG}"),
    )
    parser.add_argument("--templates", default=DEFAULT_TEMPLATE_DIR)
    parser.add_argument("--account-config", metavar="FILE", help=(
                        "Per-account config selecting taxonomy, labels, and "
                        "per-category drafting modes"))
    parser.add_argument("--taxonomy-confirmation", metavar="FILE", help=(
                        "Private artifact recording which categories the "
                        "account owner has reviewed"))
    parser.add_argument("--template-approval", metavar="FILE", help=(
                        "Private per-template approval artifact binding each "
                        "reviewed template key to the digest of its wording"))
    parser.add_argument("--templates-approved", metavar="KEYS", help=(
                        "Comma-separated template keys approved for this "
                        "supervised run (per-category; does NOT pin wording)"))
    parser.add_argument("--ai-drafting-approval", metavar="FILE", help=(
                        "Private account/category approval for AI-generated "
                        "unsent drafts; does not bind exact wording"))
    parser.add_argument("--state-path", default=DEFAULT_STATE_PATH)
    parser.add_argument("--status-path", default=DEFAULT_STATUS_PATH,
                        help="Private PII-free atomic run-status JSON")
    parser.add_argument("--lock-dir", default=DEFAULT_LOCK_DIR,
                        help="Private directory for crash-safe run locks")
    parser.add_argument(
        "--token-path",
        help="Separate Gmail token file (for example tokens/coach.json)",
    )
    parser.add_argument("--lookback-months", type=int, default=2)
    parser.add_argument("--overlap-days", type=int, default=3)
    parser.add_argument("--max-scan", type=int)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--max-body-chars", type=int, default=DEFAULT_MAX_BODY_CHARS,
        help=f"Maximum cleaned current-message characters sent to Gemini "
             f"(default: {DEFAULT_MAX_BODY_CHARS})",
    )
    parser.add_argument(
        "--estimate-only", action="store_true",
        help="Read metadata and estimate work; make zero Gemini calls and writes",
    )
    parser.add_argument(
        "--dry-run", dest="apply", action="store_false",
        help=("Prevent Gmail writes; still reads Gmail and may call Gemini "
              "(already the default)"),
    )
    parser.add_argument(
        "--apply", dest="apply", action="store_true",
        help="Allow label/draft writes after confirmation",
    )
    parser.set_defaults(apply=False)
    parser.add_argument("--yes", action="store_true")
    parser.add_argument(
        "--scheduled", action="store_true",
        help="Redact unattended output to counts and safe error codes",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Permit another daily scan today; idempotency checks still apply",
    )
    args = parser.parse_args(argv)
    for name in ("lookback_months", "overlap_days", "max_scan", "limit"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error(f"--{name.replace('_', '-')} must be greater than zero")
    if args.yes and not args.apply:
        parser.error("--yes is meaningful only with --apply")
    if args.estimate_only and args.apply:
        parser.error("--estimate-only cannot be combined with --apply")
    try:
        validate_max_body_chars(args.max_body_chars)
    except ValueError as exc:
        parser.error(str(exc))
    if args.state_path != DEFAULT_STATE_PATH:
        if args.status_path == DEFAULT_STATUS_PATH:
            args.status_path = str(Path(args.state_path).with_name("daily-status.json"))
        if args.lock_dir == DEFAULT_LOCK_DIR:
            args.lock_dir = str(Path(args.state_path).parent / "locks")
    return args


def _safe_error_code(error):
    value = str(error or "").casefold()
    if "existing_manual_draft" in value:
        return "existing_manual_draft"
    if "processed label" in value:
        return "processed_label_failed"
    if "label" in value:
        return "label_write_failed"
    if "draft" in value:
        return "draft_write_failed"
    return "unexpected_message_failure"


def _estimate_metadata(messages, account_labels, config, state, own_address,
                       limit=None):
    attach_label_names(messages, account_labels)
    processed_name = config.system["processed"]
    counts = {
        "already_processed": 0,
        "automated": 0,
        "invalid_metadata": 0,
        "gemini_candidates": 0,
    }
    for message in messages:
        record = state.record_for(message["id"])
        if (processed_name in message.get("_label_names", [])
                or record.get("status") == "complete"):
            counts["already_processed"] += 1
            continue
        headers = {}
        for name in SAFETY_HEADERS:
            values = get_header_values(message, name)
            headers[name.casefold()] = (
                ", ".join(values) if name in {"From", "Reply-To"}
                else (values[0] if values else "")
            )
        delivery = assess_delivery_headers(headers, own_address=own_address)
        if delivery["status"] == "automated":
            counts["automated"] += 1
        elif delivery["status"] != "normal":
            counts["invalid_metadata"] += 1
        else:
            counts["gemini_candidates"] += 1
            if limit is not None and counts["gemini_candidates"] >= limit:
                break
    return counts


def _run_locked(args, classifier, config, templates, state, status):
    counts = {
        "scanned": 0, "classified": 0, "labeled": 0, "drafted": 0,
        "needs_review": 0, "skipped": 0, "failures": 0,
    }

    def done(code, error_codes=()):
        status.finish(code == 0, counts, error_codes=error_codes)
        return code

    local_timezone = getattr(args, "local_timezone", LOCAL_TIMEZONE)
    today = dt.datetime.now(local_timezone).date()
    if args.mode == "daily" and state.already_ran_today(today) and not args.force:
        print(f"Daily triage already completed for {today}; nothing contacted or changed.")
        return done(0)

    query = (
        build_initial_query(args.lookback_months)
        if args.mode == "initial"
        else build_daily_query(args.overlap_days)
    )
    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()
    own_address = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get("emailAddress", "")
    )
    # The daily processor scans an inbox query, not one label, so no label
    # name is passed; an artifact scoped to a label is refused outright.
    assert_profile_matches_account(args.profile, own_address)
    args.taxonomy_confirmation = load_taxonomy_confirmation(
        args.taxonomy_confirmation, own_address
    )
    args.template_approvals = build_template_approvals(
        args.template_approval,
        parse_approved_names(args.templates_approved),
        own_address,
    )
    args.ai_drafting_approvals = load_ai_drafting_approval(
        args.ai_drafting_approval, own_address, args.profile.categories
    )

    account_labels = fetch_account_labels(service, throttle)
    missing = validate_required_labels(account_labels, config)
    if missing:
        print("Daily triage is blocked; run setup_labels.py first. Missing:")
        for name in missing:
            print(f"  {name}")
        counts["failures"] = 1
        return done(2, ["required_labels_missing"])

    year_labels, category_labels = build_label_index(
        account_labels, config.years, config.categories
    )
    print(f"Gmail query: {query}")
    message_ids = list_message_ids_by_query(
        service, query, throttle, max_scan=args.max_scan,
        progress=not args.scheduled,
    )
    counts["scanned"] = len(message_ids)

    if args.estimate_only:
        messages, failures = fetch_message_metadata(
            service, message_ids, throttle
        )
        estimate = _estimate_metadata(
            messages, account_labels, config, state, own_address, args.limit
        )
        counts["skipped"] = (
            estimate["already_processed"] + estimate["automated"]
            + estimate["invalid_metadata"] + len(failures)
        )
        counts["failures"] = len(failures)
        candidate_count = estimate["gemini_candidates"]
        generic_enabled = any(
            mode == MODE_GENERIC
            for mode in getattr(args.profile, "drafting_modes", {}).values()
        )
        maximum_model_calls = candidate_count * (2 if generic_enabled else 1)
        minimum_seconds = max(0, candidate_count - 1) * THROTTLE_SECONDS
        maximum_spacing = max(0, maximum_model_calls - 1) * THROTTLE_SECONDS
        print("\nEstimate only (metadata reads; zero Gemini calls; zero Gmail writes):")
        print(f"  scanned:                 {len(message_ids)}")
        print(f"  already processed:       {estimate['already_processed']}")
        print(f"  automated before Gemini: {estimate['automated']}")
        print(f"  invalid metadata:        {estimate['invalid_metadata']}")
        print(f"  Gemini candidates:       {estimate['gemini_candidates']}")
        print(f"  classification calls:    up to {candidate_count}")
        if generic_enabled:
            print(f"  AI draft calls:          up to {candidate_count}")
            print(f"  total model calls:       up to {maximum_model_calls}")
        print(f"  minimum model spacing:   {minimum_seconds:.0f} seconds")
        if generic_enabled:
            print(f"  maximum planned spacing: {maximum_spacing:.0f} seconds")
        print("  actual time may be longer because of Gmail latency and retries")
        return done(1 if failures else 0,
                    ["metadata_fetch_failed"] if failures else [])

    processed_name = config.system["processed"]

    def _already_processed(message):
        attach_label_names([message], account_labels)
        return (processed_name in message.get("_label_names", [])
                or state.record_for(message["id"]).get("status") == "complete")

    def _would_consume_budget(message):
        # Every message this run touches costs at least the processed label,
        # so an unprocessed message is exactly one that spends budget.
        return not _already_processed(message)

    # limit bounds the Gmail read itself. Passing it here is the whole point:
    # the post-fetch loop below would otherwise stop at the limit only after
    # every message in the window had already been downloaded in full.
    messages, failures = fetch_messages(
        service, message_ids, throttle,
        limit=args.limit, is_candidate=_would_consume_budget,
    )
    for message_id, failure in failures:
        display_id = opaque_id(message_id) if args.scheduled else message_id
        print(f"  ERROR {display_id}: fetch failed ({failure}); skipped")
    counts["failures"] += len(failures)
    attach_label_names(messages, account_labels)
    candidates, skipped = select_candidates(
        messages, args.limit, _already_processed
    )
    counts["skipped"] += skipped

    plans = []
    for message in candidates:
        email = message_to_email(
            message, max_body_chars=args.max_body_chars,
            own_address=own_address, profile=args.profile,
        )
        email["message_id"] = message["id"]
        plan = plan_message(
            email, templates, year_labels, category_labels,
            no_label=False, templates_dir=args.templates,
            classifier=classifier,
            template_approvals=getattr(args, "template_approvals", None),
            taxonomy_confirmation=getattr(args, "taxonomy_confirmation", None),
            profile=getattr(args, "profile", None),
            ai_drafting_approvals=getattr(
                args, "ai_drafting_approvals", None
            ),
        )
        add_daily_review_policy(plan, config)
        plan["processed_label"] = processed_name
        plans.append(plan)

    counts["classified"] = sum(plan["classification_called"] for plan in plans)
    counts["skipped"] += sum(
        bool(plan.get("suppression_code")) for plan in plans
    )
    draft_threads = (
        list_existing_draft_threads(service, throttle) if plans else {}
    )
    reconcile_existing_drafts(plans, state, draft_threads, config)

    # The write budget is applied HERE, before the preview, so a dry run
    # reports exactly what an --apply run would do. Computing it in the
    # executor alone would make the preview overstate every bounded run.
    plans, deferred = plans_within_write_budget(plans, args.limit)

    if not args.scheduled:
        print("\nInteractive preview: subjects and message metadata may be visible below.")
        print()
        print_plan_table(plans)
        print()
        print_notes(plans)
        preview = render_draft_preview(plans, scheduled=args.scheduled)
        if preview:
            print(preview)
    label_count = sum(len(plan["decision"].add) + 1 for plan in plans)
    draft_count = sum(plan["template"] is not None for plan in plans)
    review_count = sum(plan["needs_review"] for plan in plans)
    counts["needs_review"] = review_count
    print(f"\nCandidates:   {len(plans)}")
    print(f"Label adds:   up to {label_count}")
    print(f"Drafts:       up to {draft_count}")
    print(f"Needs review: {review_count}")
    if args.limit is not None:
        print(f"Write budget: {label_count + draft_count} of {args.limit} "
              "(--limit bounds label adds plus drafts)")
    if deferred:
        print(f"Deferred:     {len(deferred)} candidate(s) left for the next "
              "run; they were not marked processed")
    if not plans and deferred:
        cheapest = min(plan_write_cost(plan) for plan in deferred)
        print(f"\n--limit {args.limit} is too small to process any message; "
              f"the cheapest pending one needs {cheapest} writes. "
              "Raise --limit to make progress.")

    if not args.apply:
        print("\nDry run - Gmail was read and Gemini may have been called, but no "
              "Gmail labels or drafts were changed. Private run status was updated.")
        return done(1 if failures else 0,
                    ["message_fetch_failed"] if failures else [])
    if not plans:
        # Deferred work means the day is NOT done. Marking it complete here
        # would set the same-day guard and hide the remainder until tomorrow.
        if args.mode == "daily" and not failures and not deferred:
            state.mark_daily_complete(today)
        print("Nothing eligible to process; no Gmail writes or draft log created.")
        return done(1 if failures else 0,
                    ["message_fetch_failed"] if failures else [])
    if plans and not args.yes and not confirm(label_count, draft_count):
        print("Aborted; no Gmail writes were made.")
        return done(1, ["operator_aborted"])

    # Refresh after the human confirmation window. A manual draft created
    # while the preview was open must still suppress our draft creation.
    if plans:
        draft_threads = list_existing_draft_threads(service, throttle)
        reconcile_existing_drafts(plans, state, draft_threads, config)

    log_path = new_log_path(prefix="daily-triage")
    header = [
        f"daily triage {dt.datetime.now(local_timezone).isoformat(timespec='seconds')}",
        f"mode: {args.mode}",
        "contains program-created draft ids only; no messages were sent",
    ]
    error_codes = []
    with DraftLog(log_path, header) as draft_log:
        for plan in plans:
            try:
                labels, _draft_id, plan_errors = execute_daily_plan(
                    service, plan, account_labels, throttle, draft_log,
                    state, draft_threads,
                )
                counts["labeled"] += len(labels)
            except Exception as exc:
                plan_errors = [f"unexpected failure ({type(exc).__name__})"]
            for error in plan_errors:
                counts["failures"] += 1
                code = _safe_error_code(error)
                error_codes.append(code)
                display_id = (
                    opaque_id(plan["email"]["message_id"])
                    if args.scheduled else plan["email"]["message_id"]
                )
                print(f"  ERROR {display_id}: {code} ({error.rsplit('(', 1)[-1].rstrip(')')})")
        counts["drafted"] = draft_log.count

    if args.mode == "daily" and counts["failures"] == 0 and not deferred:
        state.mark_daily_complete(today)
    print(f"\nCompleted {len(plans)} candidates with {counts['failures']} errors.")
    if counts["drafted"]:
        print(f"Draft-id log: {log_path}")
    return done(1 if counts["failures"] else 0, error_codes)


def main(argv=None, classifier=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.scheduled else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        args.profile = _load_account_profile(args.account_config)
        args.local_timezone = ZoneInfo(args.profile.timezone)
        if args.state_path == DEFAULT_STATE_PATH:
            args.state_path = args.profile.state_path
            if args.status_path == DEFAULT_STATUS_PATH:
                args.status_path = args.profile.status_path
            if args.lock_dir == DEFAULT_LOCK_DIR:
                args.lock_dir = args.profile.lock_dir
        if args.templates == DEFAULT_TEMPLATE_DIR:
            args.templates = args.profile.template_dir
        config = load_triage_label_config(args.config, profile=args.profile)
        templates = load_templates(args.templates)
        # Structure only; the account binding is enforced in _run_locked
        # once the authenticated Gmail account is known.
        precheck_template_approval(args.template_approval)
        precheck_ai_drafting_approval(args.ai_drafting_approval)
        state = DailyState(args.state_path).load(
            restrict_permissions=args.apply or args.scheduled
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Configuration/state error ({type(exc).__name__}); no Gmail contact occurred.")
        status = RunStatus(args.status_path)
        status.start("configuration")
        status.finish(False, {"failures": 1}, ["configuration_or_state_invalid"])
        return 2

    status = RunStatus(args.status_path)
    status.start(f"{args.mode}:{'estimate' if args.estimate_only else 'apply' if args.apply else 'dry-run'}")

    target_key = "\0".join((
        str(Path(args.state_path).resolve()),
        str(Path(args.token_path).resolve()) if args.token_path else "default-token",
    ))
    lock = ExclusiveRunLock(args.lock_dir, target_key)
    try:
        with lock:
            try:
                return _run_locked(args, classifier, config, templates, state, status)
            except Exception as exc:
                print(f"Daily triage stopped safely ({type(exc).__name__}).")
                status.finish(False, {"failures": 1}, ["unexpected_run_failure"])
                return 1
    except AlreadyRunningError:
        print("Another triage run is already active for this target; nothing contacted or changed.")
        status.finish(False, {"skipped": 1}, ["lock_already_held"], lock_held=True)
        return LOCKED_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main())
