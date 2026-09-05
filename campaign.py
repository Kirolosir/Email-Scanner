"""Campaign mail merge: create one draft reply per unique sender under a
Gmail label, using a plain-text body file as the message.

This is separate from the classifier and does not touch the Gemini API.

NEVER SENDS. The only write calls in this file are draft creation and, for
an explicitly requested --undo, moving the run's drafts to Trash. The OAuth
scope required for these workflows can technically send mail; safety is
enforced by having no send operation in production code and by a regression
test that rejects one.

Every created draft id is appended to a timestamped log file as it is
created, so an interrupted or unwanted run can be rolled back with
--undo. The rollback touches only the ids in that log, never drafts
written by hand, and moves them to Trash rather than deleting them so
the rollback is itself reversible.

Usage:
    python campaign.py LABEL BODY_FILE [options]
    python campaign.py --undo LOGFILE [--dry-run] [--yes]

Run --help for the full option list. Two are easy to misread: --limit applies
after dedupe and exclusion, and --max-scan is what bounds the Gmail read --
without it every run scans the full label (~9,000 messages) before it can
honor --limit.
"""
import argparse
import datetime
import json
import os
import re
import sys

from googleapiclient.errors import HttpError

from account_profile import load_profile as _load_profile
from gmail_auth import get_gmail_service
from gmail_retry import gmail_execute

_PROFILE = _load_profile()
# Shared with triage.py. Re-exported from this module so existing callers
# and tests that import them from campaign keep working.
from gmail_common import (  # noqa: F401
    LIST_PAGE_SIZE,
    QUOTA_UNITS_PER_SECOND,
    UNITS_DRAFTS_CREATE,
    UNITS_DRAFTS_GET,
    UNITS_MESSAGES_GET,
    UNITS_MESSAGES_LIST,
    UNITS_MESSAGES_TRASH,
    QuotaThrottle,
    build_draft_body,
    list_all_message_ids,
    normalize_address,
)
from message_safety import assess_delivery_headers

# Where per-run draft-id logs are written.
DRAFT_LOG_DIR = _PROFILE.draft_log_dir

# Messages per metadata batch request. Gmail accepts up to 100; 50 keeps
# individual batches small enough to retry cheaply when one fails.
METADATA_BATCH_SIZE = 50

METADATA_HEADERS = [
    "From", "Reply-To", "Auto-Submitted", "Precedence", "List-Unsubscribe",
    "X-Auto-Response-Suppress", "Subject", "Message-ID",
]
PROTECTED_CAMPAIGN_LABELS = set(_PROFILE.protected_labels)


class DraftLog:
    """Appends created draft ids to a log file, one per line.

    Each id is flushed to the OS immediately rather than buffered: the
    whole point of the log is to survive an interrupted run, and a run
    killed with Ctrl-C partway through 2,000 drafts is exactly the case
    that needs rolling back. A buffered log would lose its tail.

    Leading '#' lines record what the run was, so a log found later can
    be identified; the --undo reader skips them.

    The file is created on the FIRST recorded id, not at construction. A run
    that drafts nothing leaves no log behind, so every file in draft-logs/ is
    a real rollback handle rather than a header-only stub. With drafting off
    for every category, the eager version wrote one empty file per run.

    Deferring the open must not defer the failure, though: if the log were
    unwritable, opening it lazily would surface that only after the first
    draft already existed, leaving a created draft with nothing to roll it
    back. __init__ therefore still prepares and checks the directory, and
    only the file creation waits.
    """

    def __init__(self, path, header_lines=()):
        self.path = path
        self._header_lines = tuple(header_lines)
        self._file = None
        self.count = 0
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        # Fail now, not after the first draft is already created.
        if not os.access(parent or ".", os.W_OK | os.X_OK):
            raise OSError(
                f"draft log directory {parent or '.'} is not writable; "
                "refusing to create drafts that could not be rolled back"
            )

    @property
    def created(self):
        """True once this run has actually written a log file."""
        return self._file is not None

    def _open(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.chmod(self.path, 0o600)
        self._file = os.fdopen(fd, "a", encoding="utf-8")
        for line in self._header_lines:
            self._file.write(f"# {line}\n")
        self._file.flush()

    def record(self, draft_id):
        if self._file is None:
            self._open()
        self._file.write(f"{draft_id}\n")
        self._file.flush()
        self.count += 1

    def close(self):
        if self._file and not self._file.closed:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


def new_log_path(now=None, prefix="campaign"):
    """Timestamped log path for a run, e.g.
    draft-logs/campaign-20260831-142233.log (prefix 'undo' for the
    message ids an undo run moved to Trash)."""
    now = now or datetime.datetime.now()
    return os.path.join(
        DRAFT_LOG_DIR, f"{prefix}-{now.strftime('%Y%m%d-%H%M%S')}.log"
    )


def load_draft_ids(path):
    """Read draft ids from a run log, skipping '#' comments and blanks."""
    draft_ids = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            draft_ids.append(line)
    return draft_ids


def canonical_address(address, aliases=None):
    """Return the configured canonical address for a normalized address.

    Aliases are explicit only; this function never guesses that two addresses
    belong to the same person. Chained mappings are supported and cycles are
    rejected when the mapping is loaded.
    """
    current = normalize_address(address) or (address or "").strip().lower()
    aliases = aliases or {}
    seen = set()
    while current in aliases:
        if current in seen:
            raise ValueError(f"alias mapping contains a cycle at {current!r}")
        seen.add(current)
        current = aliases[current]
    return current


def load_aliases(path):
    """Load explicit ``alias,canonical`` address mappings from a text file."""
    if not path:
        return {}

    aliases = {}
    with open(path, encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 2:
                raise ValueError(
                    f"{path}:{line_number}: expected alias,canonical"
                )
            alias = normalize_address(parts[0])
            canonical = normalize_address(parts[1])
            if not alias or not canonical:
                raise ValueError(
                    f"{path}:{line_number}: both addresses must be valid"
                )
            if alias == canonical:
                continue
            aliases[alias] = canonical

    # Resolve each entry now so cycles/malformed chains fail before Gmail use.
    return {alias: canonical_address(canonical, aliases)
            for alias, canonical in aliases.items()}


def load_exclusions(path, aliases=None):
    """Read a file of email addresses to skip, one per line.

    Blank lines and lines starting with # are ignored. Addresses are
    normalized the same way sender addresses are, so the comparison is
    case-insensitive and tolerates 'Name <addr>' formatting.
    """
    if not path:
        return set()

    exclusions = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            address = normalize_address(line) or line.lower()
            exclusions.add(canonical_address(address, aliases))
    return exclusions


def load_campaign_approval(path, label_name, actual_account, aliases=None):
    """Load one private, human-reviewed recipient allowlist.

    The artifact is bound to the exact Gmail account and label. Duplicate
    canonical recipients are rejected instead of silently collapsed so an
    alias/configuration mistake cannot broaden a campaign unnoticed.
    """
    if not path:
        return None
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="utf-8") as approval_file:
        document = json.load(approval_file)
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("campaign approval must be a version 1 JSON object")
    raw_account = document.get("account", "")
    if not isinstance(raw_account, str):
        raise ValueError("campaign approval account must be an email string")
    account = normalize_address(raw_account)
    label = document.get("label")
    recipients = document.get("approved_recipients")
    if not account or account != normalize_address(actual_account):
        raise ValueError("campaign approval account does not match Gmail account")
    if label != label_name:
        raise ValueError("campaign approval label does not match requested label")
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("campaign approval must contain approved_recipients")

    approved = set()
    for index, value in enumerate(recipients, start=1):
        if not isinstance(value, str):
            raise ValueError(f"approved recipient {index} must be an email string")
        address = normalize_address(value)
        if not address:
            raise ValueError(f"approved recipient {index} is malformed")
        canonical = canonical_address(address, aliases)
        if canonical in approved:
            raise ValueError(
                "campaign approval has a duplicate canonical recipient; "
                "review aliases and approval entries"
            )
        approved.add(canonical)
    return approved


PLACEHOLDER_PATTERN = re.compile(
    r"\[[^\]\n]*(?:placeholder|replace|insert|registration|register|link|url|"
    r"date|time)[^\]\n]*\]",
    re.IGNORECASE,
)


def find_unresolved_placeholders(body_text):
    """Return obvious unresolved bracketed campaign placeholders."""
    return sorted(set(match.group(0) for match in PLACEHOLDER_PATTERN.finditer(
        body_text or ""
    )))


def fetch_metadata(service, message_ids, throttle, own_address="", progress=True):
    """Fetch From/Subject/Message-ID plus threadId and internalDate for
    each message id, using batched requests to keep round trips down.

    Returns (records, failed_ids). Individual failures inside a batch are
    collected rather than raised, then retried once sequentially.
    """
    records = []
    failed_ids = []

    def callback(request_id, response, exception):
        if exception is not None:
            failed_ids.append(request_id)
            return
        records.append(_to_record(response, own_address=own_address))

    for start in range(0, len(message_ids), METADATA_BATCH_SIZE):
        chunk = message_ids[start:start + METADATA_BATCH_SIZE]
        throttle.consume(UNITS_MESSAGES_GET * len(chunk))

        batch = service.new_batch_http_request(callback=callback)
        for message_id in chunk:
            batch.add(
                service.users().messages().get(
                    userId="me",
                    id=message_id,
                    format="metadata",
                    metadataHeaders=METADATA_HEADERS,
                ),
                request_id=message_id,
            )
        try:
            batch.execute()
        except Exception:
            # A whole-batch transport failure may produce no callbacks. Queue
            # every unresolved id for the sequential retry below.
            resolved = {record["message_id"] for record in records}
            failed_ids.extend(
                message_id for message_id in chunk
                if message_id not in resolved and message_id not in failed_ids
            )
        if progress:
            print(f"  fetched {len(records)}/{len(message_ids)} headers...",
                  end="\r", flush=True)

    # One sequential retry pass for anything the batch dropped.
    still_failed = []
    for message_id in failed_ids:
        throttle.consume(UNITS_MESSAGES_GET)
        try:
            response = gmail_execute(service.users().messages().get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=METADATA_HEADERS,
            ))
        except Exception:
            still_failed.append(message_id)
            continue
        records.append(_to_record(response, own_address=own_address))

    if progress:
        print(f"  fetched {len(records)}/{len(message_ids)} headers    ")
    return records, still_failed


def _to_record(message, own_address=""):
    """Flatten a metadata-format message resource into the fields the
    dedupe and draft steps need."""
    grouped_headers = {}
    for header in message.get("payload", {}).get("headers", []):
        grouped_headers.setdefault(header["name"].casefold(), []).append(
            header.get("value", "")
        )
    headers = {
        name: (", ".join(values) if name in {"from", "reply-to"} else values[0])
        for name, values in grouped_headers.items()
    }
    delivery = assess_delivery_headers(headers, own_address=own_address)
    return {
        "message_id": message["id"],
        "thread_id": message["threadId"],
        # internalDate is a string of epoch millis; int() so the
        # most-recent comparison is numeric, not lexicographic.
        "internal_date": int(message.get("internalDate", 0)),
        "sender": delivery["sender"] or normalize_address(headers.get("from", "")),
        "reply_address": delivery["reply_address"],
        "delivery_safety": delivery,
        "subject": headers.get("subject", ""),
        "rfc_message_id": headers.get("message-id", ""),
    }


def dedupe_by_sender(records, own_address, aliases=None):
    """Collapse records to the most recent message per canonical address.

    Messages sent by the account owner are dropped: in a label of
    correspondence the owner's own replies appear as messages too, and
    without this the campaign would draft a reply addressed to himself.
    """
    best_by_sender = {}
    own_canonical = canonical_address(own_address, aliases)
    for record in records:
        sender = record["sender"]
        safety = record.get("delivery_safety", {})
        if safety and safety.get("status") != "normal":
            continue
        recipient = record.get("reply_address") or sender
        canonical = canonical_address(recipient, aliases)
        if not canonical or canonical == own_canonical:
            continue
        current = best_by_sender.get(canonical)
        if current is None or record["internal_date"] > current["internal_date"]:
            best_by_sender[canonical] = record
    return best_by_sender


def exclusions_from_labels(service, label_names, throttle, aliases=None):
    """Gather canonical sender addresses from existing labels, read-only."""
    exclusions = set()
    failures = []
    for label_name in label_names or ():
        message_ids = list_all_message_ids(service, label_name, throttle)
        records, failed_ids = fetch_metadata(service, message_ids, throttle)
        exclusions.update(
            canonical_address(record["sender"], aliases)
            for record in records if record["sender"]
        )
        failures.extend(failed_ids)
    return exclusions, failures


def select_targets(by_sender, exclusions=(), limit=None, approved=None):
    """Filter, newest-first sort, and optionally limit canonical recruits."""
    excluded = set(exclusions or ())
    approved_set = None if approved is None else set(approved)
    eligible = [
        record for key, record in by_sender.items()
        if key not in excluded and (approved_set is None or key in approved_set)
    ]
    eligible.sort(key=lambda record: record["internal_date"], reverse=True)
    targets = eligible[:limit] if limit is not None else eligible
    return eligible, targets


def preview_lines(targets, maximum=20):
    """Return privacy-minimal recipient/subject lines for confirmation preview."""
    return [f"{record['sender']}  |  {record['subject'][:60]}"
            for record in targets[:maximum]]


def create_drafts(service, targets, body_text, throttle, draft_log):
    """Create one draft per target, logging each id as it is created.

    Returns (created, failures). A per-draft failure is recorded and
    skipped rather than aborting the run, so one bad thread doesn't cost
    the other 1,999 drafts.

    The id is written to draft_log immediately after each create returns,
    so the log stays accurate even if the run is interrupted.
    """
    created = 0
    failures = []

    for i, record in enumerate(targets, start=1):
        throttle.consume(UNITS_DRAFTS_CREATE)
        try:
            draft = gmail_execute(service.users().drafts().create(
                userId="me", body=build_draft_body(record, body_text)
            ))
        except Exception as e:
            error_name = type(e).__name__
            failures.append((record["sender"], error_name))
            print(f"\n  FAILED {record['sender']}: {error_name}")
            continue

        draft_log.record(draft["id"])
        created += 1
        if i % 25 == 0 or i == len(targets):
            print(f"  created {created}/{len(targets)} drafts...",
                  end="\r", flush=True)

    print(f"  created {created}/{len(targets)} drafts    ")
    return created, failures


def _is_not_found(error):
    resp = getattr(error, "resp", None)
    return resp is not None and resp.status == 404


def trash_drafts(service, draft_ids, throttle, trashed_log=None):
    """Move exactly the given drafts to Trash.

    Each draft is resolved to its underlying message id, and that message
    is trashed rather than the draft being deleted outright - so an undo
    run that turns out to be a mistake can still be walked back from
    Trash within Gmail's ~30 day retention window.

    Returns (trashed, missing, failures). A 404 at either step means the
    draft is already gone (undo run twice, or removed by hand) and counts
    as 'missing', not an error. Any other failure is collected so one bad
    id doesn't strand the rest.

    Trashed message ids are written to trashed_log as they go, so a
    restore has an exact list to work from.
    """
    trashed = 0
    missing = 0
    failures = []

    for i, draft_id in enumerate(draft_ids, start=1):
        # Resolve draft -> underlying message id.
        throttle.consume(UNITS_DRAFTS_GET)
        try:
            draft = gmail_execute(service.users().drafts().get(
                userId="me", id=draft_id, format="minimal"
            ))
        except Exception as e:
            if _is_not_found(e):
                missing += 1
            else:
                failures.append((draft_id, f"get failed: {e}"))
                print(f"\n  FAILED {draft_id}: {e}")
            continue

        message_id = draft.get("message", {}).get("id")
        if not message_id:
            failures.append((draft_id, "draft has no message id"))
            print(f"\n  FAILED {draft_id}: draft resource had no message id")
            continue

        throttle.consume(UNITS_MESSAGES_TRASH)
        try:
            gmail_execute(service.users().messages().trash(
                userId="me", id=message_id
            ))
        except Exception as e:
            if _is_not_found(e):
                missing += 1
            else:
                failures.append((draft_id, f"trash failed: {e}"))
                print(f"\n  FAILED {draft_id}: {e}")
            continue

        if trashed_log is not None:
            trashed_log.record(message_id)
        trashed += 1
        if i % 25 == 0 or i == len(draft_ids):
            print(f"  trashed {trashed}/{len(draft_ids)} drafts...",
                  end="\r", flush=True)

    print(f"  trashed {trashed}/{len(draft_ids)} drafts    ")
    return trashed, missing, failures


def run_undo(service, log_path, throttle, dry_run=False, assume_yes=False):
    """Roll back a campaign run by deleting exactly the ids in its log."""
    draft_ids = load_draft_ids(log_path)

    print("\n--- Undo summary ---")
    print(f"Log file:          {log_path}")
    print(f"Draft ids in log:  {len(draft_ids)}")

    if not draft_ids:
        print("\nNo draft ids in that log; nothing to undo.")
        return 0

    unique_ids = list(dict.fromkeys(draft_ids))
    if len(unique_ids) != len(draft_ids):
        print(f"Unique ids:        {len(unique_ids)} "
              f"({len(draft_ids) - len(unique_ids)} duplicate lines ignored)")
        draft_ids = unique_ids

    preview = draft_ids[:10]
    print(f"\nFirst {len(preview)} ids:")
    for draft_id in preview:
        print(f"  {draft_id}")
    if len(draft_ids) > len(preview):
        print(f"  ... and {len(draft_ids) - len(preview)} more")

    if dry_run:
        print("\nDry run - nothing trashed.")
        return 0

    print("\nThese drafts will be moved to Trash, not deleted outright - "
          "Gmail keeps trashed items for about 30 days, so this step is "
          "itself reversible.")
    print("Only ids listed in this log are touched; hand-written drafts "
          "are never affected.")

    if not assume_yes and not confirm_undo(len(draft_ids)):
        print("Aborted; nothing trashed.")
        return 1

    trashed_path = new_log_path(prefix="undo")
    header = [
        f"undo run {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"source log: {log_path}",
        f"drafts to trash: {len(draft_ids)}",
        "these are message ids, now in Trash; untrash to restore",
    ]

    print(f"\nLogging trashed message ids to {trashed_path}\n")
    with DraftLog(trashed_path, header) as trashed_log:
        try:
            trashed, missing, failures = trash_drafts(
                service, draft_ids, throttle, trashed_log
            )
        except KeyboardInterrupt:
            print(f"\n\nInterrupted after trashing {trashed_log.count} drafts.")
            print(f"Trashed message ids logged to {trashed_path}")
            return 130

    print(f"\nDone. Moved {trashed} drafts to Trash.")
    print(f"Trashed message ids logged to {trashed_path}")
    if missing:
        print(f"{missing} already gone (not found) - likely already undone.")
    if failures:
        print(f"{len(failures)} failed:")
        for draft_id, error in failures[:10]:
            print(f"  {draft_id}: {error}")
    return 0


def _prompt_yes(prompt):
    try:
        answer = input(prompt)
    except EOFError:
        print("\nNo interactive input available; re-run with --yes to proceed.")
        return False
    return answer.strip().lower() == "yes"


def confirm(count):
    """Interactive gate before any writes happen."""
    return _prompt_yes(
        f"\nCreate {count} drafts in this Gmail account? Type 'yes' to proceed: "
    )


def confirm_undo(count):
    """Interactive gate before trashing drafts."""
    return _prompt_yes(
        f"\nMove {count} drafts to Trash? Type 'yes' to proceed: "
    )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create one draft reply per unique sender under a Gmail label."
    )
    # Optional so --undo can run without them; validated below.
    parser.add_argument("label", nargs="?", help="Gmail label name to scan")
    parser.add_argument("body_file", nargs="?",
                        help="Plain-text file containing the reply body")
    parser.add_argument("--exclude", metavar="FILE",
                        help="File of email addresses to skip, one per line")
    parser.add_argument("--exclude-label", action="append", default=[],
                        metavar="LABEL", help=(
                            "Skip senders found under this existing Gmail label; "
                            "repeatable and read-only"))
    parser.add_argument("--aliases", metavar="FILE", help=(
                        "Explicit alias mapping file: alias,canonical per line"))
    parser.add_argument("--approval", metavar="FILE", help=(
                        "Private account/label-bound reviewed recipient allowlist"))
    parser.add_argument("--token-path", help=(
                        "Separate Gmail token file (for example tokens/coach.json)"))
    parser.add_argument("--limit", type=int, metavar="N",
                        help="Create at most N drafts (after dedupe/exclusion)")
    parser.add_argument("--max-scan", type=int, metavar="N",
                        help="Stop scanning after N messages (testing aid)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would happen; change nothing")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt")
    parser.add_argument("--undo", metavar="LOGFILE",
                        help="Move exactly the drafts listed in LOGFILE to Trash")

    args = parser.parse_args(argv)

    if args.undo:
        if args.label or args.body_file:
            parser.error("--undo takes no label or body_file")
    elif not args.label or not args.body_file:
        parser.error("label and body_file are required unless --undo is used")

    for name in ("limit", "max_scan"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error(f"--{name.replace('_', '-')} must be greater than zero")

    return args


def main(argv=None):
    args = parse_args(argv)

    if args.undo:
        service = None if args.dry_run else get_gmail_service(
            token_path=args.token_path
        )
        return run_undo(
            service,
            args.undo,
            QuotaThrottle(),
            dry_run=args.dry_run,
            assume_yes=args.yes,
        )

    with open(args.body_file, encoding="utf-8") as f:
        body_text = f.read()
    if not body_text.strip():
        print(f"Body file {args.body_file!r} is empty; refusing to draft blank replies.")
        return 1

    placeholders = find_unresolved_placeholders(body_text)
    if placeholders:
        print("Campaign body contains unresolved placeholders:")
        for placeholder in placeholders:
            print(f"  {placeholder}")
        print("Real draft writes are blocked until the final coach-approved "
              "text and links replace them.")
        if not args.dry_run:
            return 2

    try:
        aliases = load_aliases(args.aliases)
        exclusions = load_exclusions(args.exclude, aliases)
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}")
        return 1

    protected_unreviewed = (
        args.label in PROTECTED_CAMPAIGN_LABELS and not args.approval
    )
    if protected_unreviewed and not args.dry_run:
        print(
            f"Real campaign writes for protected label {args.label!r} are blocked. "
            "Provide a private, coach-reviewed --approval artifact bound to the "
            "exact Gmail account and label."
        )
        return 2

    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()

    try:
        label_exclusions, exclusion_failures = exclusions_from_labels(
            service, args.exclude_label, throttle, aliases
        )
    except Exception as exc:
        print(f"Could not read exclusion label: {exc}")
        return 1
    exclusions.update(label_exclusions)

    own_address = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get("emailAddress", "")
    )
    try:
        approved = load_campaign_approval(
            args.approval, args.label, own_address, aliases
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Campaign approval error: {exc}")
        return 2

    print(f"Scanning label {args.label!r}...")
    message_ids = list_all_message_ids(
        service, args.label, throttle, max_scan=args.max_scan
    )

    records, failed_ids = fetch_metadata(
        service, message_ids, throttle, own_address=own_address
    )
    by_sender = dedupe_by_sender(records, own_address, aliases)

    eligible_before_approval, _unused = select_targets(
        by_sender, exclusions, limit=None
    )
    eligible, targets = select_targets(
        by_sender, exclusions, args.limit, approved=approved
    )
    excluded_count = len(by_sender) - len(eligible_before_approval)
    unapproved_count = len(eligible_before_approval) - len(eligible)

    print("\n--- Summary ---")
    print(f"Label:                  {args.label}")
    print(f"Account:                {own_address}")
    print(f"Body file:              {args.body_file} ({len(body_text)} chars)")
    print(f"Messages found:         {len(message_ids)}")
    if failed_ids:
        print(f"Metadata fetch failed:  {len(failed_ids)} (skipped)")
    print(f"Deduplication:          normalized email address"
          f"{' plus explicit aliases' if aliases else ''}")
    print(f"Unique safe recipients: {len(by_sender)}")
    if aliases:
        print(f"Alias mappings:         {len(aliases)}")
    if args.exclude_label:
        print(f"Exclusion labels read:  {len(args.exclude_label)}")
        print(f"Label senders excluded: {len(label_exclusions)}")
        if exclusion_failures:
            print(f"Exclusion fetch failed: {len(exclusion_failures)} (skipped)")
    print(f"Excluded:               {excluded_count}")
    print(f"Eligible after exclude: {len(eligible_before_approval)}")
    if approved is not None:
        print(f"Reviewed allowlist:     {len(approved)}")
        print(f"Not approved/skipped:   {unapproved_count}")
    elif protected_unreviewed:
        print("Approval status:        UNREVIEWED - real writes are blocked")
    if args.limit:
        print(f"Limited by --limit:     {args.limit}")
    print(f"Drafts to create:       {len(targets)}")

    preview = targets[:20]
    if preview:
        print(f"\nFirst {len(preview)} recipients:")
        for line in preview_lines(targets):
            print(f"  {line}")
        if len(targets) > len(preview):
            print(f"  ... and {len(targets) - len(preview)} more")

    if args.dry_run:
        if placeholders:
            print("\nDry run - no drafts created; real writes remain BLOCKED by "
                  "the unresolved placeholders above.")
        else:
            print("\nDry run - no drafts created.")
        if protected_unreviewed:
            print(
                f"Real writes remain BLOCKED until the {args.label} population "
                "is audited and a reviewed --approval artifact is supplied."
            )
        return 0

    if not targets:
        print("\nNothing to do.")
        return 0

    if not args.yes and not confirm(len(targets)):
        print("Aborted; no drafts created.")
        return 1

    # Opened only after confirmation, so a dry run or an aborted run
    # leaves no stray log file behind.
    log_path = new_log_path()
    header = [
        f"campaign run {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"label: {args.label}",
        f"account: {own_address}",
        f"body file: {args.body_file}",
        f"targets: {len(targets)}",
        f"undo with: python campaign.py --undo {log_path}",
    ]

    print(f"\nDraft ids will be logged to {log_path} if any are created")
    with DraftLog(log_path, header) as draft_log:
        try:
            created, failures = create_drafts(
                service, targets, body_text, throttle, draft_log
            )
        except KeyboardInterrupt:
            # The log is flushed per draft, so whatever was created is
            # already recorded - surface the path before exiting.
            print(f"\n\nInterrupted after {draft_log.count} drafts.")
            print(f"Draft ids logged to {log_path}")
            print(f"To roll back what was created:  "
                  f"python campaign.py --undo {log_path}")
            return 130

    print(f"\nDone. Created {created} drafts.")
    if created:
        print(f"Draft ids logged to {log_path}")
        print(f"To roll this run back:  python campaign.py --undo {log_path}")
    if failures:
        print(f"{len(failures)} failed:")
        for sender, error in failures[:10]:
            print(f"  {sender}: {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
