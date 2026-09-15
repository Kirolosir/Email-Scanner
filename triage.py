"""Triage pipeline: read messages from a Gmail label, classify each with
Gemini, apply matching labels, and create approved template or generated replies.

Flow per message:
    read -> classify -> decide_labels -> apply_labels -> template -> draft

NEVER SENDS. The only write calls add approved existing labels and create
drafts. The required OAuth scope can technically send mail; this repository
contains no send operation, and an automated source regression test enforces
that boundary.

Created draft ids are logged to a timestamped file in the same format
campaign.py uses, so a triage run can be rolled back with:
    python campaign.py --undo draft-logs/triage-YYYYMMDD-HHMMSS.log

Usage:
    python triage.py LABEL [options]

Options:
    --templates DIR   Template directory (default: templates/).
    --limit N         Process at most N messages.
    --dry-run         Report what would happen; change nothing.
    --yes             Skip the confirmation prompt.
    --no-label        Classify and draft, but apply no labels at all.
"""
import argparse
import contextvars
import datetime
import hashlib
import json
import logging
import os
import queue
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from googleapiclient.errors import HttpError

from campaign import DraftLog, new_log_path
from gemini_client import (
    SUPPORTED_GRAD_YEARS,
    VALID_CATEGORIES,
    VALID_CONFIDENCE,
    analyze_and_draft,
    classify,
    generate_reply,
)
import account_profile as _PROFILE_MOD
from account_profile import load_profile as _load_profile
import drafting as _DRAFTING
from drafting import resolve_mode as _resolve_drafting_mode
from drafting import (
    AiDraftingApprovals as _AiDraftingApprovals,
    build_generic_body as _build_generic_body,
    build_safe_fallback_body as _build_safe_fallback_body,
    load_ai_drafting_approval as _load_ai_drafting_approval,
    precheck_ai_drafting_approval as _precheck_ai_drafting_approval,
)
from account_profile import (
    assert_profile_matches_account as _assert_profile_matches_account,
)
from taxonomy import TaxonomyConfirmation as _TaxonomyConfirmation
from taxonomy import load_taxonomy_confirmation as _load_taxonomy_confirmation
from gmail_auth import get_gmail_service
from gmail_retry import describe_failure, gmail_execute

_PROFILE = _load_profile()
# Confirms nothing; the fail-closed default for the taxonomy gate.
_EMPTY_CONFIRMATION = _TaxonomyConfirmation()
from gmail_common import (
    UNITS_DRAFTS_CREATE,
    UNITS_MESSAGES_GET,
    QuotaThrottle,
    build_draft_body,
    list_all_message_ids,
    normalize_address,
)
from gmail_labeler import (
    apply_labels,
    build_label_index,
    decide_labels,
    fetch_account_labels,
    log_decision,
)
from gmail_reader import get_header, get_header_values, get_plain_text_body
from message_safety import (
    DEFAULT_MAX_BODY_CHARS,
    assess_delivery_headers,
    clean_current_message,
    extract_grad_year_evidence,
)
from triage_limits import plans_within_draft_limit, validate_max_drafts

DEFAULT_TEMPLATE_DIR = _PROFILE.template_dir
# Sourced from the account profile; previously duplicated in gmail_labeler.py.
RECRUIT_YEAR_CATEGORIES = set(_PROFILE.evidence_categories)

logger = logging.getLogger(__name__)

SAFETY_HEADERS = (
    "From", "Reply-To", "Auto-Submitted", "Precedence", "List-Unsubscribe",
    "X-Auto-Response-Suppress", "Message-ID", "Subject",
)


def load_templates(templates_dir):
    """Load every template in the directory, keyed by filename stem.

    Both ``<category>_<grad_year>.txt`` and ``<category>.txt`` are accepted.
    Safety checks happen during resolution so placeholder files can be named
    precisely in the report without ever being used to create a real draft.
    """
    templates = {}
    if not os.path.isdir(templates_dir):
        return templates

    for filename in sorted(os.listdir(templates_dir)):
        if not filename.endswith(".txt"):
            continue
        category = filename[:-len(".txt")]
        path = os.path.join(templates_dir, filename)
        with open(path, encoding="utf-8") as f:
            body = f.read()
        if body.strip():
            templates[category] = body
        else:
            logger.warning("Template %s is empty; ignoring it", path)
    return templates


TEMPLATE_APPROVAL_VERSION = 1
TEMPLATE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)


def is_placeholder_template(body):
    """Detect the repository's explicit placeholder-template marker."""
    return "[placeholder template" in (body or "").lower()


def template_digest(body):
    """Stable digest of one template's exact wording.

    Approval is bound to this digest so that editing a template after it was
    reviewed silently invalidates the approval instead of carrying it over to
    wording no human has read.
    """
    return "sha256:" + hashlib.sha256((body or "").encode("utf-8")).hexdigest()


class TemplateApprovals:
    """Per-template-key record of which template wording a human approved.

    Two independent forms, both opt-in and both per-key - approving
    ``recruit_intro`` can never activate drafting for ``parent``:

    * ``content_bound`` maps a template key to the digest of the exact
      wording that was reviewed. This is the durable artifact form; an edit
      to the file revokes the approval automatically.
    * ``name_only`` holds keys approved by name for a supervised run. It is
      deliberately weaker - it does NOT pin the wording - and exists for
      interactive pilots where an operator is watching each draft.

    An empty instance approves nothing, so the default is fail-closed.
    """

    def __init__(self, content_bound=None, name_only=()):
        self.content_bound = dict(content_bound or {})
        self.name_only = set(name_only or ())

    def check(self, key, body):
        """Return ``(approved, reason)`` for one template key and its body."""
        expected = self.content_bound.get(key)
        if expected is not None:
            actual = template_digest(body)
            if expected.lower() == actual.lower():
                return True, ""
            return False, (
                f"template unapproved: {key!r} wording changed since it was "
                f"reviewed (approved {expected[:14]}..., found {actual[:14]}...)"
            )
        if key in self.name_only:
            return True, ""
        return False, (
            f"template unapproved: no reviewed approval for {key!r}"
        )

    def approved_keys(self):
        return sorted(set(self.content_bound) | self.name_only)

    def describe(self):
        if not self.content_bound and not self.name_only:
            return "none (no template is approved; draft creation is blocked)"
        parts = []
        if self.content_bound:
            parts.append(
                "content-bound: " + ", ".join(sorted(self.content_bound))
            )
        if self.name_only:
            parts.append(
                "name-only (wording NOT pinned): " + ", ".join(sorted(self.name_only))
            )
        return "; ".join(parts)


def _parse_template_approval(path):
    """Read and structurally validate an approval artifact.

    Returns the raw ``(account, label, {key: digest})`` triple without
    checking the account/label binding, so a malformed file fails before any
    Gmail contact. Binding is enforced separately by
    ``load_template_approval``.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="utf-8") as approval_file:
        document = json.load(approval_file)
    if not isinstance(document, dict) or (
        document.get("version") != TEMPLATE_APPROVAL_VERSION
    ):
        raise ValueError("template approval must be a version 1 JSON object")

    raw_account = document.get("account", "")
    if not isinstance(raw_account, str):
        raise ValueError("template approval account must be an email string")
    account = normalize_address(raw_account)
    if not account:
        raise ValueError(
            "template approval must name the Gmail account it was reviewed for"
        )

    label = document.get("label")
    if label is not None and (not isinstance(label, str) or not label.strip()):
        raise ValueError(
            "template approval label must be a non-empty string when present"
        )

    approved = document.get("approved_templates")
    if not isinstance(approved, dict) or not approved:
        raise ValueError(
            "template approval must contain a non-empty approved_templates object"
        )
    digests = {}
    for key, digest in approved.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("template approval keys must be non-empty strings")
        if not isinstance(digest, str) or not TEMPLATE_DIGEST_PATTERN.match(digest):
            raise ValueError(
                f"template approval for {key!r} must be a 'sha256:<64 hex>' digest"
            )
        if key.strip() in digests:
            raise ValueError(
                f"template approval has a duplicate key {key.strip()!r}"
            )
        digests[key.strip()] = digest.strip().lower()
    return account, (label.strip() if isinstance(label, str) else None), digests


def precheck_template_approval(path):
    """Validate an artifact's structure before any Gmail contact.

    Deliberately does NOT check the account binding - the authenticated
    account is not known yet. Use it only to fail fast on a malformed file;
    ``load_template_approval`` is what actually authorizes anything.
    """
    if not path:
        return
    _parse_template_approval(path)


def load_template_approval(path, actual_account, label_name=None):
    """Load one private, human-reviewed per-template approval artifact.

    JSON shape::

        {"version": 1,
         "account": "coach@example.edu",
         "label": "INBOX",                      # optional
         "approved_templates": {"recruit_intro": "sha256:<64 hex>"}}

    Bound to the exact Gmail account, mirroring the campaign approval check,
    so an artifact reviewed against the test account cannot authorize
    drafting in the coach's mailbox. ``account`` is required.

    ``label`` is optional because the daily processor scans an inbox query
    rather than one label. When the artifact names a label it is honored
    strictly: it must equal the label being triaged, and a run with no single
    label (the daily processor) is refused rather than silently widened.

    `actual_account` is a required argument so it cannot be omitted by
    accident and quietly skip the binding.
    """
    if not path:
        return {}
    account, label, digests = _parse_template_approval(path)

    if account != normalize_address(actual_account or ""):
        raise ValueError(
            "template approval account does not match the authenticated "
            "Gmail account"
        )
    if label is not None:
        if label_name is None:
            raise ValueError(
                f"template approval is scoped to label {label!r}, but this run "
                "does not target a single label"
            )
        if label != label_name:
            raise ValueError(
                "template approval label does not match the requested label"
            )
    return digests


def build_template_approvals(approval_path, approved_names, actual_account,
                             label_name=None):
    """Combine the artifact and the supervised-run flag into one record."""
    return TemplateApprovals(
        content_bound=load_template_approval(
            approval_path, actual_account, label_name
        ),
        name_only={name.strip() for name in approved_names if name and name.strip()},
    )


def parse_approved_names(value):
    """Parse a comma-separated --templates-approved value into keys."""
    if not value:
        return set()
    return {part.strip() for part in value.split(",") if part.strip()}


def unsafe_template_paths(templates, templates_dir):
    return [
        os.path.join(templates_dir, f"{key}.txt")
        for key, body in sorted(templates.items())
        if is_placeholder_template(body)
    ]


def resolve_template(templates, category, grad_year,
                     templates_dir=DEFAULT_TEMPLATE_DIR, approvals=None,
                     valid_categories=None):
    """Resolve a verified, approved template, preferring category+year.

    Returns ``(body, key, reason)``. A template is usable for draft creation
    only when it is both:

    1. not placeholder-marked, and
    2. explicitly approved for its exact key (see TemplateApprovals).

    Placeholder files are treated as missing for write purposes. Real files
    that no human has approved are also treated as missing, reported as
    "template unapproved" - approval is checked AFTER the placeholder test,
    so approving a placeholder key can never unlock it.

    `approvals` defaults to an empty record, i.e. fail-closed: adding real
    template wording never starts drafting on its own.
    """
    permitted = (VALID_CATEGORIES if valid_categories is None
                 else valid_categories)
    if category not in permitted:
        return None, None, f"unsupported/unknown category {category!r}; not drafting"

    approvals = approvals if approvals is not None else TemplateApprovals()

    candidates = []
    if grad_year in SUPPORTED_GRAD_YEARS:
        candidates.append(f"{category}_{grad_year}")
    candidates.append(category)

    unsafe = []
    unapproved = []
    for key in candidates:
        body = templates.get(key)
        if body is None:
            continue
        if is_placeholder_template(body):
            unsafe.append(os.path.join(templates_dir, f"{key}.txt"))
            continue
        approved, why = approvals.check(key, body)
        if not approved:
            unapproved.append(why)
            continue
        return body, key, None

    # Real wording exists but is unreviewed: report that specifically, so it
    # is never confused with a missing file.
    if unapproved:
        return None, None, "; ".join(unapproved) + "; not drafting"

    required = " or ".join(
        os.path.join(templates_dir, f"{key}.txt") for key in candidates
    )
    reason = f"real template required: {required}; not drafting"
    if unsafe:
        reason += f" (placeholder unsafe: {', '.join(unsafe)})"
    return None, None, reason


def load_label_config(path, profile=None):
    """Load configurable real label names without contacting Gmail.

    JSON shape: ``{"years": {"2027": "..."}, "categories": {...}}``.
    Names are only candidates; build_label_index still filters them against
    labels that already exist in the account and never creates a label.
    """
    if not path:
        # A bound per-account config is itself the reviewed source. Legacy
        # behavior stays fail-closed when no explicit label config is given.
        if profile is not None and getattr(profile, "taxonomy", ()):
            return dict(profile.year_labels), dict(profile.category_labels)
        return {}, {}
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, dict):
        raise ValueError("label config must be a JSON object")

    def validate_map(name):
        mapping = config.get(name, {})
        if not isinstance(mapping, dict):
            raise ValueError(f"label config {name!r} must be an object")
        if not all(isinstance(k, str) and isinstance(v, str) and v.strip()
                   for k, v in mapping.items()):
            raise ValueError(f"label config {name!r} must map strings to names")
        return mapping

    return validate_map("years"), validate_map("categories")


def message_to_email(message, max_body_chars=DEFAULT_MAX_BODY_CHARS,
                     own_address="", profile=None):
    """Flatten a Gmail message resource into the dict classify() wants,
    plus the fields needed to build a threaded reply draft."""
    headers = {}
    for name in SAFETY_HEADERS:
        values = get_header_values(message, name)
        headers[name.casefold()] = (
            ", ".join(values) if name in {"From", "Reply-To"}
            else (values[0] if values else "")
        )
    cleaning = clean_current_message(
        get_plain_text_body(message), max_chars=max_body_chars
    )
    delivery = assess_delivery_headers(headers, own_address=own_address)
    effective_profile = profile if profile is not None else _PROFILE
    supported_years = (
        set(effective_profile.supported_years) or set(SUPPORTED_GRAD_YEARS)
    )
    year_evidence = extract_grad_year_evidence(
        cleaning["text"], headers.get("subject", ""), supported_years
    )
    return {
        "from": delivery["sender"] or normalize_address(headers.get("from", "")),
        "reply_address": delivery["reply_address"],
        "subject": headers.get("subject", ""),
        "body": cleaning["text"],
        "thread_id": message.get("threadId", ""),
        "rfc_message_id": headers.get("message-id", ""),
        "label_names": message.get("_label_names", []),
        "delivery_safety": delivery,
        "body_cleaning": cleaning,
        "local_year_evidence": year_evidence,
        "own_address": normalize_address(own_address),
    }


def _drafting_block(category, profile):
    """Reason to refuse drafting because the owner has not opted this
    category in. Returns a skip reason, or None.

    Drafting is off for every category until explicitly enabled, and an
    unrecognized mode resolves to off rather than to anything that drafts.
    """
    profile = profile if profile is not None else _PROFILE
    if getattr(profile, "draft_all_replyable_messages", False):
        return None
    mode = _resolve_drafting_mode(profile, category)
    if mode is None:
        # Profile does not use per-category drafting control.
        return None
    if mode == _DRAFTING.MODE_OFF:
        return (
            f"drafting is not enabled for category {category!r}; "
            "labeling only, not drafting"
        )
    return None


def _generate_global_reply(email, classification, profile, draft_generator):
    """Try at most two generated bodies, then return the fact-free fallback."""
    last_error = None
    max_words = int(
        (getattr(profile, "ai_drafting", {}) or {}).get("max_words", 180)
    )
    for attempt in range(2):
        try:
            generated = (
                draft_generator(email, classification, profile)
                if draft_generator is not None
                else generate_reply(
                    email, classification, profile=profile, max_retries=1
                )
            )
            return (
                _build_generic_body(generated, max_words=max_words),
                attempt + 1, None, False,
            )
        except Exception as exc:
            last_error = type(exc).__name__
    try:
        return _build_safe_fallback_body(profile), 2, last_error, True
    except Exception as exc:
        return None, 2, type(exc).__name__, False


def _taxonomy_block(category, confirmation, profile):
    """Reason to refuse drafting for an unconfirmed discovered category.

    Returns a skip reason, or None when drafting may proceed.

    The gate applies only when the profile carries a DISCOVERED taxonomy.
    A code-defined profile has no model-proposed names, so there is nothing
    for an owner to confirm and nothing to gate. A migrated account config
    always carries a taxonomy, and its confirmation is absent until the owner
    completes the review - migration never inherits approval from history.

    Labeling is never gated here; this function is consulted only by the
    draft chain.
    """
    profile = profile if profile is not None else _PROFILE
    taxonomy = getattr(profile, "taxonomy", ()) or ()
    if not taxonomy:
        return None

    entry = next((item for item in taxonomy if item["slug"] == category), None)
    if entry is None:
        return (
            f"category {category!r} is not in the confirmed taxonomy; "
            "not drafting"
        )

    confirmation = confirmation or _EMPTY_CONFIRMATION
    confirmed, reason = confirmation.check(entry["slug"], entry["digest"])
    if not confirmed:
        return f"{reason}; not drafting"
    return None


def plan_message(email, templates, year_labels, category_labels, no_label,
                 templates_dir=DEFAULT_TEMPLATE_DIR, classifier=None,
                 template_approvals=None, taxonomy_confirmation=None,
                 profile=None, draft_generator=None,
                 ai_drafting_approvals=None, combined_result=None):
    """Decide, without making any API calls, what should happen to one
    message: which labels to add and whether a draft can be built.

    Returns a dict with the classification, the LabelDecision, the
    template body (or None), and a reason when no draft is possible.
    """
    effective_profile = profile if profile is not None else _PROFILE
    # This is account-owner policy loaded from the reviewed profile, never a
    # classifier/model decision.  Keep the real runtime value visibly wired to
    # every global-drafting branch so omission fails closed.
    global_drafting = bool(
        getattr(effective_profile, "draft_all_replyable_messages", False)
    )
    current_account_wide_drafting_approved = bool(
        global_drafting
        and getattr(ai_drafting_approvals, "draft_all_replyable_messages", False)
        and getattr(ai_drafting_approvals, "include_bulk_messages", False)
    )
    classification_error = None
    combined_analysis = combined_result
    delivery = email.get("delivery_safety") or assess_delivery_headers(
        {"from": email.get("from", ""), "reply-to": email.get("reply_to", "")},
        own_address=email.get("own_address", ""),
    )
    cleaning = email.get("body_cleaning") or clean_current_message(email.get("body", ""))
    email["body"] = cleaning["text"]
    email["body_cleaning"] = cleaning
    email["delivery_safety"] = delivery
    if not email.get("from"):
        email["from"] = delivery.get("sender", "")
    if not email.get("reply_address"):
        email["reply_address"] = delivery.get("reply_address", "")
    supported_years = (
        set(effective_profile.supported_years) or set(SUPPORTED_GRAD_YEARS)
    )
    local_year = email.get("local_year_evidence") or extract_grad_year_evidence(
        email.get("body", ""), email.get("subject", ""), supported_years
    )
    email["local_year_evidence"] = local_year

    suppression_code = ""
    classification_called = False
    if delivery["status"] == "automated" or (
        delivery["status"] == "bulk"
        and not current_account_wide_drafting_approved
    ):
        suppression_code = "automated_message"
        classification = {
            "category": _PROFILE_MOD.SYSTEM_CATEGORY_ADMINISTRATIVE,
            "grad_year": _PROFILE_MOD.UNKNOWN,
            "sender_type": _PROFILE_MOD.SYSTEM_CATEGORY_ADMINISTRATIVE,
            "confidence": "high",
            "evidence": "deterministic automated-message headers",
            "reason": "automated message suppressed before classification",
            "valid": True,
        }
    elif delivery["status"] not in {"normal", "bulk"}:
        suppression_code = "unsafe_reply_metadata"
        classification = {
            "category": "unknown", "grad_year": "unknown",
            "sender_type": "unknown", "confidence": "low", "evidence": "",
            "reason": "reply metadata requires review", "valid": False,
        }
    elif not cleaning["meaningful"]:
        suppression_code = "empty_cleaned_body"
        classification = {
            "category": "unknown", "grad_year": "unknown",
            "sender_type": "unknown", "confidence": "low", "evidence": "",
            "reason": "no meaningful current-message text", "valid": False,
        }
    else:
        try:
            classification_called = True
            if combined_analysis is not None:
                classification = combined_analysis
            elif (global_drafting and current_account_wide_drafting_approved
                  and classifier is None and draft_generator is None):
                combined_analysis = analyze_and_draft(
                    email, profile=effective_profile
                )
                classification = combined_analysis
            else:
                classification = (
                    classifier(email)
                    if classifier is not None
                    else classify(email, profile=effective_profile)
                )
            if not isinstance(classification, dict):
                raise ValueError("classifier result was not an object")
        except Exception as exc:
            classification_error = type(exc).__name__
            logger.warning(
                "Classification failed for message %s (%s); continuing as unknown",
                email.get("message_id", "unknown"), classification_error,
            )
            classification = {
                "category": "unknown", "grad_year": "unknown",
                "sender_type": "unknown", "confidence": "unknown",
                "evidence": "", "valid": False,
            }

    raw_category = classification.get("category")
    category = raw_category.strip().lower() if isinstance(raw_category, str) else "unknown"
    # Validate against the profile actually in force. VALID_CATEGORIES is
    # bound at import time to the default profile, so a per-account profile
    # must supply its own vocabulary or its categories would all normalize
    # to "unknown".
    _effective_profile = effective_profile
    if category not in _effective_profile.valid_categories:
        category = "unknown"
    raw_grad_year = classification.get("grad_year")
    grad_year = raw_grad_year.strip() if isinstance(raw_grad_year, str) else "unknown"
    if grad_year not in supported_years:
        grad_year = "unknown"
    raw_sender_type = classification.get("sender_type")
    sender_type = (
        raw_sender_type.strip().lower()
        if isinstance(raw_sender_type, str) else ""
    )
    # Offline/test classifiers written before sender_type existed remain
    # deterministic. Live parse_result always supplies and validates it.
    if not sender_type:
        sender_type = _effective_profile.category_sender_types.get(
            category, _PROFILE_MOD.UNKNOWN
        )
    if sender_type not in _PROFILE_MOD.VALID_SENDER_TYPES:
        sender_type = _PROFILE_MOD.UNKNOWN
    raw_confidence = classification.get("confidence")
    if isinstance(raw_confidence, str):
        confidence = raw_confidence.strip().lower()
    elif "valid" not in classification:
        # Backward compatibility for deterministic test/demo classifiers only.
        # The live parser always emits an explicit validated confidence value.
        confidence = "high"
    else:
        confidence = "unknown"
    if confidence not in VALID_CONFIDENCE:
        confidence = "unknown"
    classification_valid = (
        classification_error is None
        and classification.get("valid", True) is not False
        and confidence in VALID_CONFIDENCE
    )
    expected_sender = _effective_profile.category_sender_types.get(category)
    if expected_sender is not None and sender_type != expected_sender:
        classification_valid = False
    classification_actionable = classification_valid and confidence == "high"
    local_grad_year = local_year.get("grad_year", "unknown")
    classification = dict(
        classification,
        category=category,
        grad_year=grad_year,
        sender_type=sender_type,
        confidence=confidence,
        local_grad_year=local_grad_year,
        local_evidence_codes=list(local_year.get("evidence_codes", [])),
        valid=classification_valid,
        actionable=classification_actionable,
    )

    label_classification = classification
    year_policy_skip = None
    year_evidence_conflict = False
    if not classification_actionable:
        label_classification = dict(
            classification, category="unknown", grad_year="unknown",
            sender_type="unknown",
        )
        fallback_category = getattr(
            _effective_profile, "fallback_category", ""
        )
        if global_drafting and fallback_category:
            label_classification = dict(
                label_classification, category=fallback_category
            )
    matching_rule = next(
        (
            rule for rule in (_effective_profile.evidence_rules or ())
            if rule.get("expected_value") in {grad_year, local_grad_year}
        ),
        None,
    )
    year_label_eligible = False
    if matching_rule is not None:
        year_label_eligible = (
            sender_type in matching_rule["require_sender_type"]
            and category in matching_rule["require_categories"]
            and confidence == matching_rule["min_confidence"]
        )

    if not classification_actionable:
        pass
    elif matching_rule is not None and year_label_eligible:
        mentions_year = (
            grad_year != "unknown" or local_grad_year != "unknown"
            or local_year.get("ambiguous", False)
        )
        if mentions_year and not (
            grad_year == local_grad_year != "unknown"
            and not local_year.get("ambiguous", False)
        ):
            label_classification = dict(classification, grad_year="unknown")
            year_evidence_conflict = True
            year_policy_skip = (
                "model graduation year lacks matching deterministic "
                "current-message evidence"
            )
    elif grad_year != "unknown":
        label_classification = dict(classification, grad_year="unknown")
        year_policy_skip = (
            f"year {grad_year} not applied: sender/category is not a verified "
            "recruit message"
        )

    label_classification = dict(
        label_classification,
        year_label_eligible=year_label_eligible and not year_evidence_conflict,
    )

    if no_label:
        decision = decide_labels(classification, [], {}, {})
        decision.skips = ["--no-label: labeling disabled for this run"]
        decision.add = []
    else:
        decision = decide_labels(
            label_classification,
            email["label_names"],
            year_labels,
            category_labels,
        )
        if year_policy_skip:
            decision.skips.append(year_policy_skip)

    template = template_key = None
    draft_source = None
    draft_generation_called = False
    draft_generation_attempts = 0
    draft_generation_error = None
    draft_fallback_used = False
    draft_skip = None
    if suppression_code == "automated_message":
        draft_skip = "bounce or unsafe automated return path; not drafting"
    elif suppression_code == "unsafe_reply_metadata":
        draft_skip = "unsafe or ambiguous reply metadata; not drafting"
    elif suppression_code == "empty_cleaned_body" and not global_drafting:
        draft_skip = "no meaningful current-message text; not drafting"
    elif (not email.get("reply_address") or not email.get("thread_id")
          or not email.get("rfc_message_id")):
        draft_skip = "malformed message missing safe reply metadata; not drafting"
    elif global_drafting:
        needs_generic_fallback = bool(
            classification_error
            or not classification_valid
            or confidence != "high"
            or year_evidence_conflict
            or decision.conflicts
            or suppression_code == "empty_cleaned_body"
        )
        draft_category = (
            getattr(_effective_profile, "fallback_category", "")
            if needs_generic_fallback else category
        )
        taxonomy_block = _taxonomy_block(
            draft_category, taxonomy_confirmation, profile
        )
        if taxonomy_block:
            draft_skip = taxonomy_block
        else:
            approvals = (
                ai_drafting_approvals
                if ai_drafting_approvals is not None
                else _AiDraftingApprovals()
            )
            protected = bool(
                (
                    set(email.get("label_names", ())) | set(decision.add)
                ) & set(_effective_profile.protected_labels)
            )
            approved, reason = approvals.check(
                draft_category, carries_protected_label=protected
            )
            if not approved:
                draft_skip = reason
            else:
                generation_classification = dict(
                    classification,
                    category=draft_category,
                    grad_year=(
                        "unknown" if needs_generic_fallback else grad_year
                    ),
                )
                draft_generation_called = True
                if (combined_analysis is not None
                        and isinstance(combined_analysis.get("reply_body"), str)):
                    try:
                        max_words = int(
                            (_effective_profile.ai_drafting or {}).get(
                                "max_words", 180
                            )
                        )
                        template = _build_generic_body(
                            combined_analysis["reply_body"], max_words=max_words
                        )
                        draft_generation_attempts = 1
                    except Exception as exc:
                        draft_generation_error = type(exc).__name__
                        template = _build_safe_fallback_body(_effective_profile)
                        draft_fallback_used = True
                else:
                    template, draft_generation_attempts, draft_generation_error, \
                        draft_fallback_used = _generate_global_reply(
                            email, generation_classification, _effective_profile,
                            draft_generator,
                        )
                if template is None:
                    draft_skip = (
                        "draft generation and safe fallback failed; "
                        "not drafting"
                    )
                else:
                    template_key = (
                        f"fallback:{draft_category}"
                        if draft_fallback_used else f"ai:{draft_category}"
                    )
                    draft_source = "fallback" if draft_fallback_used else "ai"
    else:
        if classification_error:
            draft_skip = "classification failed; not drafting"
        elif not classification_valid:
            draft_skip = "classification was invalid or ambiguous; not drafting"
        elif confidence != "high":
            draft_skip = "classification confidence is not high; not drafting"
        elif year_evidence_conflict:
            draft_skip = "graduation-year evidence requires manual review; not drafting"
        elif decision.conflicts:
            draft_skip = "label classification conflict requires manual review; not drafting"
        elif _taxonomy_block(category, taxonomy_confirmation, profile):
            draft_skip = _taxonomy_block(category, taxonomy_confirmation, profile)
        elif _drafting_block(category, profile):
            draft_skip = _drafting_block(category, profile)
        else:
            mode = _resolve_drafting_mode(_effective_profile, category)
            if mode == _DRAFTING.MODE_GENERIC:
                approvals = (
                    ai_drafting_approvals
                    if ai_drafting_approvals is not None
                    else _AiDraftingApprovals()
                )
                protected = bool(
                    (
                        set(email.get("label_names", ())) | set(decision.add)
                    ) & set(_effective_profile.protected_labels)
                )
                approved, reason = approvals.check(
                    category, carries_protected_label=protected
                )
                if not approved:
                    draft_skip = reason
                else:
                    try:
                        draft_generation_called = True
                        draft_generation_attempts = 1
                        generated = (
                            draft_generator(email, classification, _effective_profile)
                            if draft_generator is not None
                            else generate_reply(
                                email, classification, profile=_effective_profile
                            )
                        )
                        template = _build_generic_body(
                            generated,
                            max_words=int(
                                (_effective_profile.ai_drafting or {}).get(
                                    "max_words", 180
                                )
                            ),
                        )
                        template_key = f"ai:{category}"
                        draft_source = "ai"
                    except Exception as exc:
                        draft_generation_error = type(exc).__name__
                        draft_skip = (
                            "draft generation failed safely; not drafting"
                        )
            else:
                template, template_key, draft_skip = resolve_template(
                    templates, category, grad_year, templates_dir,
                    approvals=template_approvals,
                    valid_categories=_effective_profile.valid_categories,
                )
                if template is not None:
                    draft_source = "template"

    # Account-wide mode keeps technically unsafe, uncertain, or fallback
    # cases visible to the owner even though it never invents a reply target.
    # This is part of the shared planner so on-demand and scheduled paths use
    # the same policy.
    if global_drafting and not no_label:
        requires_review = bool(
            draft_skip
            or draft_fallback_used
            or not classification_actionable
            or year_evidence_conflict
            or decision.conflicts
        )
        review_label = _effective_profile.system_labels.get("needs_review", "")
        if (
            requires_review
            and review_label
            and review_label not in email.get("label_names", ())
            and review_label not in decision.add
        ):
            decision.add.append(review_label)

    return {
        "email": email,
        "classification": classification,
        "category": category,
        "grad_year": grad_year,
        "sender_type": sender_type,
        "confidence": confidence,
        "decision": decision,
        "template": template,
        "template_key": template_key,
        "draft_source": draft_source,
        "draft_skip": draft_skip,
        "draft_generation_called": draft_generation_called,
        "draft_generation_attempts": draft_generation_attempts,
        "draft_generation_error": draft_generation_error,
        "draft_fallback_used": draft_fallback_used,
        "classification_error": classification_error,
        "classification_called": classification_called,
        "suppression_code": suppression_code,
        "current_account_wide_drafting_approved": (
            current_account_wide_drafting_approved
        ),
        "year_evidence_conflict": year_evidence_conflict,
    }


def execute_plan(service, plan, account_labels, throttle, draft_log):
    """Apply labels and create the draft for one planned message.

    Returns (labels_applied, draft_created, errors).
    """
    email = plan["email"]
    errors = []
    labels_applied = []
    draft_created = False

    if plan["decision"].add:
        try:
            apply_labels(
                service, email["message_id"], plan["decision"].add,
                account_labels, throttle,
            )
            labels_applied = list(plan["decision"].add)
        except Exception as e:
            errors.append(f"label failed: {e}")

    if plan["template"] is not None:
        record = {
            "sender": email["from"],
            "reply_address": email.get("reply_address", email["from"]),
            "subject": email["subject"],
            "rfc_message_id": email["rfc_message_id"],
            "thread_id": email["thread_id"],
        }
        throttle.consume(UNITS_DRAFTS_CREATE)
        try:
            draft = gmail_execute(service.users().drafts().create(
                userId="me", body=build_draft_body(record, plan["template"])
            ))
            draft_log.record(draft["id"])
            draft_created = True
        except Exception as e:
            errors.append(f"draft failed: {e}")

    return labels_applied, draft_created, errors


def fetch_messages(service, message_ids, throttle, limit=None,
                   is_candidate=None, services=None):
    """Fetch full messages, attaching resolved label names for the
    labeler's 'already labeled?' checks.

    ``limit`` bounds the GMAIL READ, not just what the caller keeps. Once
    ``limit`` fetched messages have satisfied ``is_candidate``, fetching
    stops. Without this a ``--limit 15`` run downloaded the full body of
    every message in the window and discarded all but fifteen - slow, and an
    unnecessary read of thousands of messages' contents.

    ``is_candidate`` decides which fetched messages count toward the limit,
    so messages skipped as already-processed do not consume the budget. When
    it is omitted every fetched message counts.
    """
    service_list = list(services or [service])
    if (len(service_list) > 1 and message_ids
            and (limit is None or limit >= len(message_ids))):
        pool = queue.Queue()
        for item in service_list:
            pool.put(item)

        def _fetch(message_id):
            worker_service = pool.get()
            try:
                throttle.consume(UNITS_MESSAGES_GET)
                return gmail_execute(worker_service.users().messages().get(
                    userId="me", id=message_id, format="full"
                ))
            finally:
                pool.put(worker_service)

        ordered = [None] * len(message_ids)
        failures = []
        parent_context = contextvars.copy_context()
        with ThreadPoolExecutor(max_workers=len(service_list)) as executor:
            futures = {
                executor.submit(
                    parent_context.copy().run, _fetch, message_id
                ): (index, message_id)
                for index, message_id in enumerate(message_ids)
            }
            for future in as_completed(futures):
                index, message_id = futures[future]
                try:
                    ordered[index] = future.result()
                except Exception as exc:
                    failures.append((message_id, describe_failure(exc)))
        return [message for message in ordered if message is not None], failures

    messages = []
    failures = []
    selected = 0
    for message_id in message_ids:
        if limit is not None and selected >= limit:
            break
        throttle.consume(UNITS_MESSAGES_GET)
        try:
            message = gmail_execute(service.users().messages().get(
                userId="me", id=message_id, format="full"
            ))
        except Exception as exc:
            # Record the real status, not just 'HttpError'. A transient
            # rate limit and a permanent permission error read identically
            # otherwise, which is how 143 retryable failures looked fatal.
            failures.append((message_id, describe_failure(exc)))
            continue
        messages.append(message)
        if is_candidate is None or is_candidate(message):
            selected += 1
    return messages, failures


def fetch_message_metadata(service, message_ids, throttle):
    """Fetch only reviewed headers/label ids; never download message bodies."""
    messages = []
    failures = []
    for message_id in message_ids:
        throttle.consume(UNITS_MESSAGES_GET)
        try:
            message = gmail_execute(service.users().messages().get(
                userId="me", id=message_id, format="metadata",
                metadataHeaders=list(SAFETY_HEADERS),
            ))
        except Exception as exc:
            # Record the real status, not just 'HttpError'. A transient
            # rate limit and a permanent permission error read identically
            # otherwise, which is how 143 retryable failures looked fatal.
            failures.append((message_id, describe_failure(exc)))
            continue
        messages.append(message)
    return messages, failures


def attach_label_names(messages, account_labels):
    """Map each message's label ids back to names, in place."""
    id_to_name = {v: k for k, v in account_labels.items()}
    for message in messages:
        message["_label_names"] = [
            id_to_name[label_id]
            for label_id in message.get("labelIds", [])
            if label_id in id_to_name
        ]
    return messages


def print_plan_table(plans):
    header = f"{'#':<3} | {'Subject':<34} | {'Category':<15} | {'Yr':<5} | {'Labels':<28} | Draft"
    print(header)
    print("-" * len(header))
    for i, plan in enumerate(plans, start=1):
        subject = plan["email"]["subject"][:34]
        labels = ", ".join(plan["decision"].add) or "-"
        draft = "yes" if plan["template"] is not None else "no"
        print(f"{i:<3} | {subject:<34} | {plan['category']:<15} | "
              f"{plan['grad_year'] or '-':<5} | {labels[:28]:<28} | {draft}")


def print_notes(plans):
    for i, plan in enumerate(plans, start=1):
        for conflict in plan["decision"].conflicts:
            print(f"  [{i}] CONFLICT: {conflict}")
        if plan["draft_skip"]:
            print(f"  [{i}] {plan['draft_skip']}")


def confirm(label_count, draft_count):
    prompt = (f"\nApply {label_count} labels and create {draft_count} drafts? "
              "Type 'yes' to proceed: ")
    try:
        return input(prompt).strip().lower() == "yes"
    except EOFError:
        print("\nNo interactive input available; re-run with --yes.")
        return False


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Classify a Gmail label and prepare unsent draft replies."
    )
    parser.add_argument("label", help="Gmail label to triage")
    parser.add_argument("--templates", default=DEFAULT_TEMPLATE_DIR,
                        help=f"Template directory (default: {DEFAULT_TEMPLATE_DIR})")
    parser.add_argument("--label-config", metavar="FILE", help=(
                        "JSON mapping of years/categories to existing label names"))
    parser.add_argument("--account-config", metavar="FILE", help=(
                        "Per-account config selecting the taxonomy, labels, "
                        "and drafting policy for this inbox"))
    parser.add_argument("--taxonomy-confirmation", metavar="FILE", help=(
                        "Private artifact recording which discovered "
                        "categories the account owner has reviewed"))
    parser.add_argument("--template-approval", metavar="FILE", help=(
                        "Private per-template approval artifact binding each "
                        "reviewed template key to the digest of its exact wording"))
    parser.add_argument("--templates-approved", metavar="KEYS", help=(
                        "Comma-separated template keys approved for this "
                        "supervised run (per-category; does NOT pin wording)"))
    parser.add_argument(
        "--drafting-approval", "--ai-drafting-approval",
        dest="ai_drafting_approval", metavar="FILE", help=(
                        "Private account-wide or legacy category approval for "
                        "generated unsent drafts"))
    parser.add_argument("--limit", type=int, metavar="N",
                        help="Process at most N messages")
    parser.add_argument(
        "--max-drafts", type=int, metavar="N",
        help="Create at most N new Gmail drafts; zero disables drafting",
    )
    parser.add_argument("--token-path", help=(
                        "Separate Gmail token file for this account"))
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would happen; change nothing")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt")
    parser.add_argument("--no-label", action="store_true",
                        help="Classify and draft, but apply no labels")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be greater than zero")
    try:
        validate_max_drafts(args.max_drafts)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    templates = load_templates(args.templates)
    if not templates:
        print(f"No templates found in {args.templates!r}; template-mode "
              "categories cannot draft, but approved generated drafting can continue.")
    else:
        print(f"Loaded {len(templates)} templates: {', '.join(sorted(templates))}")
    unsafe = unsafe_template_paths(templates, args.templates)
    if unsafe:
        print("Unsafe placeholder templates (never used for draft creation):")
        for path in unsafe:
            print(f"  {path}")

    # Structure only: catches a malformed artifact before any Gmail contact.
    # The account binding cannot be checked until we know who we authorized as.
    try:
        precheck_template_approval(args.template_approval)
        _precheck_ai_drafting_approval(args.ai_drafting_approval)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Drafting approval error: {exc}")
        return 1

    # Structural only; account bindings are enforced after authorization.
    try:
        profile = _load_profile(args.account_config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Account config error: {exc}")
        return 1
    if args.account_config:
        print(f"Account config: {args.account_config}")
        print(f"  categories: {', '.join(sorted(profile.categories))}")
        modes = dict(getattr(profile, "drafting_modes", {}) or {})
        enabled = sorted(k for k, v in modes.items() if v != _DRAFTING.MODE_OFF)
        print(f"  drafting enabled for: {', '.join(enabled) or 'nothing'}")

    try:
        configured_years, configured_categories = load_label_config(
            args.label_config, profile=profile
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Invalid label configuration: {exc}")
        return 1

    service = get_gmail_service(token_path=args.token_path)
    throttle = QuotaThrottle()

    own_address = normalize_address(
        gmail_execute(service.users().getProfile(userId="me")).get("emailAddress", "")
    )

    # Now that the authenticated account is known, enforce every binding.
    try:
        _assert_profile_matches_account(profile, own_address)
        taxonomy_confirmation = _load_taxonomy_confirmation(
            args.taxonomy_confirmation, own_address
        )
        ai_drafting_approvals = _load_ai_drafting_approval(
            args.ai_drafting_approval, own_address, profile.categories,
            profile=profile,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Account/taxonomy binding error: {exc}")
        return 1
    if profile.taxonomy:
        print(f"Taxonomy confirmed for: {taxonomy_confirmation.describe()}")
    print(f"Drafting approvals: {ai_drafting_approvals.describe()}")

    try:
        template_approvals = build_template_approvals(
            args.template_approval,
            parse_approved_names(args.templates_approved),
            own_address,
            args.label,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Template approval error: {exc}")
        return 1
    print(f"Template approvals: {template_approvals.describe()}")
    if template_approvals.name_only:
        print("  WARNING: --templates-approved approves by name only; it does "
              "not pin wording. Use --template-approval for durable runs.")

    account_labels = fetch_account_labels(service, throttle)
    year_labels, category_labels = build_label_index(
        account_labels,
        year_labels=configured_years,
        category_labels=configured_categories,
    )
    if args.no_label:
        print("--no-label: labeling disabled for this run")
    else:
        print(f"Matched {len(year_labels)} year labels and "
              f"{len(category_labels)} category labels in the account")

    print(f"\nScanning label {args.label!r}...")
    message_ids = list_all_message_ids(
        service, args.label, throttle, max_scan=args.limit
    )
    messages, fetch_failures = fetch_messages(service, message_ids, throttle)
    for message_id, error_type in fetch_failures:
        print(f"  ERROR {message_id}: fetch failed ({error_type}); skipped")
    attach_label_names(messages, account_labels)

    plans = []
    for message in messages:
        email = message_to_email(
            message, own_address=own_address, profile=profile
        )
        email["message_id"] = message["id"]
        plans.append(
            plan_message(email, templates, year_labels, category_labels,
                         args.no_label, templates_dir=args.templates,
                         template_approvals=template_approvals,
                         taxonomy_confirmation=taxonomy_confirmation,
                         profile=profile,
                         ai_drafting_approvals=ai_drafting_approvals)
        )

    plans, deferred_drafts = plans_within_draft_limit(
        plans, args.max_drafts
    )

    print()
    print_plan_table(plans)
    print()
    print_notes(plans)

    label_count = sum(len(p["decision"].add) for p in plans)
    draft_count = sum(1 for p in plans if p["template"] is not None)
    conflicts = sum(len(p["decision"].conflicts) for p in plans)

    print(f"\nMessages:  {len(plans)}")
    print(f"Labels:    {label_count}")
    print(f"Drafts:    {draft_count}")
    print(f"Conflicts: {conflicts} (left for manual review)")
    if deferred_drafts:
        print(f"Deferred:  {len(deferred_drafts)} message(s) because "
              "--max-drafts was reached; no labels were applied to them")

    if args.dry_run:
        print("\nDry run - nothing changed.")
        return 0
    if not label_count and not draft_count:
        print("\nNothing to do.")
        return 0
    if not args.yes and not confirm(label_count, draft_count):
        print("Aborted; nothing changed.")
        return 1

    log_path = new_log_path(prefix="triage")
    header = [
        f"triage run {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"label: {args.label}",
        f"undo with: python campaign.py --undo {log_path}",
    ]

    print(f"\nDraft ids will be logged to {log_path} if any are created\n")
    applied = created = 0
    with DraftLog(log_path, header) as draft_log:
        try:
            for plan in plans:
                try:
                    labels, drafted, errors = execute_plan(
                        service, plan, account_labels, throttle, draft_log
                    )
                except Exception as exc:
                    labels, drafted = [], False
                    errors = [f"unexpected message failure: {type(exc).__name__}"]
                applied += len(labels)
                created += 1 if drafted else 0
                log_decision(plan["email"]["message_id"], plan["decision"])
                for error in errors:
                    print(f"  ERROR {plan['email']['subject'][:40]}: {error}")
        except KeyboardInterrupt:
            print(f"\n\nInterrupted after {draft_log.count} drafts.")
            print(f"Roll back with: python campaign.py --undo {log_path}")
            return 130

    print(f"\nDone. Applied {applied} labels, created {created} drafts.")
    if created:
        print(f"Roll back with: python campaign.py --undo {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
