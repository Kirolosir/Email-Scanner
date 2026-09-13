"""Account-wide and legacy per-category approval for unsent drafting.

Drafting is off until the owner creates a separate account-bound approval.
New profiles may request one-time drafting for every safely replyable message.
Legacy profiles can still choose per category:

  * ``template`` - the owner supplies wording, which passes the existing
    wording-bound, account-bound template approval gate unchanged.
  * ``generic``  - free-form model-written replies for that category only.
    Generic mode never depends on a wording-bound template.

Generic drafting has its own account-bound approval artifact. It approves
categories, not exact wording, so an owner can edit model guidance or edit each
Gmail draft without regenerating template digests. Protected-label messages
need an additional boolean acknowledgement in that artifact. This keeps the
year-label evidence gate separate from the decision to prepare an unsent
reply.

Drafts carry no machine-added preamble. They are written to be read and sent
by the owner, so the safety property they rest on is that nothing is ever
sent automatically: every generated reply lands as an unsent Gmail draft and
waits for a human to send or discard it.
"""
import hashlib
import json
import os
import re

MODE_OFF = "off"
MODE_TEMPLATE = "template"
MODE_GENERIC = "generic"
VALID_DRAFTING_MODES = frozenset({MODE_OFF, MODE_TEMPLATE, MODE_GENERIC})

AI_DRAFTING_APPROVAL_VERSION = 1
LEGACY_GLOBAL_DRAFTING_APPROVAL_VERSION = 2
PREVIOUS_GLOBAL_DRAFTING_APPROVAL_VERSION = 3
GLOBAL_DRAFTING_APPROVAL_VERSION = 4
_LEGACY_GENERATOR_NAME = "\x41\x49"
AI_DRAFTING_ACKNOWLEDGEMENT = (
    "I approve generated unsent drafts for the listed categories and "
    "understand that every draft must be reviewed before sending."
)
GLOBAL_DRAFTING_ACKNOWLEDGEMENT = (
    "I approve generated unsent drafts for every message with a safe "
    "reply address outside Spam, Trash, Sent, and Drafts, and understand "
    "that every draft must be reviewed before sending."
)
LEGACY_GLOBAL_DRAFTING_ACKNOWLEDGEMENT = (
    "I approve generated unsent drafts for every message with a safe "
    "reply address, understand that automated and bulk mail is never "
    "drafted, and understand that every draft must be reviewed before "
    "sending."
)
LEGACY_AI_DRAFTING_ACKNOWLEDGEMENT = (
    f"I approve {_LEGACY_GENERATOR_NAME}-generated unsent drafts for the "
    "listed categories and understand that every draft must be reviewed "
    "before sending."
)
PREVIOUS_GLOBAL_DRAFTING_ACKNOWLEDGEMENT = (
    f"I approve {_LEGACY_GENERATOR_NAME}-generated unsent drafts for every "
    "message with a safe reply address outside Spam, Trash, Sent, and Drafts, "
    "and understand that every draft must be reviewed before sending."
)
ORIGINAL_GLOBAL_DRAFTING_ACKNOWLEDGEMENT = (
    f"I approve {_LEGACY_GENERATOR_NAME}-generated unsent drafts for every "
    "message with a safe reply address, understand that automated and bulk "
    "mail is never drafted, and understand that every draft must be reviewed "
    "before sending."
)
_SLUG = re.compile(r"^[a-z][a-z0-9_]*$")
_HEADER_LINE = re.compile(
    r"(?im)^\s*(?:to|from|cc|bcc|subject)\s*:"
)
_ACCOUNT_ACTION_CLAIM = re.compile(
    r"(?i)\b(?:i|we)(?:'ve| have)?\s+(?:already\s+)?"
    r"(?:sent|forwarded|deleted|labelled|labeled|authorized|approved)\b"
)
_INTERNAL_DISCLOSURE = re.compile(
    r"(?i)\b(?:system prompt|developer instructions?|api key|access token|"
    r"refresh token|internal classification)\b"
)
_SENSITIVE_DISCLOSURE = re.compile(
    r"(?ix)(?:"
    r"\b(?:one[- ]time|verification|authentication|security)\s+code\b"
    r"|\b(?:password|passcode|pin)\b"
    r"|\b(?:account|routing|card|invoice)\s*(?:number|no\.?|\#)?\s*"
    r"(?:is\s*)?[:#-]?\s*\d"
    r"|\b\d{3}-\d{2}-\d{4}\b"
    r"|\b(?:\d[ -]?){13,19}\b"
    r"|[$€£]\s*\d"
    r")"
)

MAX_GENERATED_REPLY_CHARS = 12_000
SAFE_FALLBACK_ACKNOWLEDGEMENT = "Thank you for your message."

UNSAFE_BULK_PHRASE_TEMPLATE = (
    "I approve unreviewed generated drafting for all {count} categories on {account}"
)


class DraftingConfigError(ValueError):
    """Raised for a drafting configuration that cannot be safely honored."""


class AiDraftingApprovals:
    """Account-bound permission to generate unsent drafts.

    Unlike template approval, this deliberately does not bind exact wording:
    generated text changes for every email. The stable permission boundary is
    the configured category set and whether protected-label messages may also
    receive a generated draft.
    """

    def __init__(self, account="", categories=(), allow_protected_labels=False,
                 draft_all_replyable_messages=False, policy_digest="",
                 include_bulk_messages=False):
        self.account = (account or "").strip().lower()
        self.categories = frozenset(categories or ())
        self.allow_protected_labels = bool(allow_protected_labels)
        self.draft_all_replyable_messages = bool(draft_all_replyable_messages)
        self.policy_digest = str(policy_digest or "")
        self.include_bulk_messages = bool(include_bulk_messages)

    def check(self, category, carries_protected_label=False):
        if not self.draft_all_replyable_messages and category not in self.categories:
            return False, (
                f"generated drafting is not approved for category {category!r}; "
                "not drafting"
            )
        if carries_protected_label and not self.allow_protected_labels:
            return False, (
                "drafting approval does not include protected-label "
                "messages; not drafting"
            )
        return True, ""

    def describe(self):
        if self.draft_all_replyable_messages:
            prefix = "all replyable messages"
        elif not self.categories:
            return "none (generated draft creation is blocked)"
        else:
            prefix = ", ".join(sorted(self.categories))
        suffix = (
            "; protected-label messages approved"
            if self.allow_protected_labels
            else "; protected-label messages blocked"
        )
        return prefix + suffix


def drafting_policy_digest(profile, allow_protected_labels=False):
    """Bind global activation to every setting that can shape a draft.

    The digest contains normalized configuration only, never message data or
    secrets. A taxonomy, label, guidance, signature, fallback, evidence, or
    protected-permission change therefore invalidates the activation.
    """
    taxonomy = [
        {
            "slug": entry["slug"],
            "digest": entry.get("digest", ""),
            "label": entry.get("label"),
            "mode": (getattr(profile, "drafting_modes", {}) or {}).get(
                entry["slug"], MODE_OFF
            ),
            "guidance": (getattr(profile, "drafting_guidance", {}) or {}).get(
                entry["slug"], ""
            ),
        }
        for entry in sorted(getattr(profile, "taxonomy", ()) or (),
                            key=lambda item: item["slug"])
    ]
    evidence = [
        {
            "label": rule.get("label", ""),
            "expected_value": rule.get("expected_value", ""),
            "require_sender_type": sorted(rule.get("require_sender_type", ())),
            "require_categories": sorted(rule.get("require_categories", ())),
            "min_confidence": rule.get("min_confidence", ""),
        }
        for rule in sorted(getattr(profile, "evidence_rules", ()) or (),
                           key=lambda item: (item.get("label", ""),
                                             item.get("expected_value", "")))
    ]
    document = {
        "account": (getattr(profile, "account", "") or "").strip().lower(),
        "timezone": getattr(profile, "timezone", "") or "",
        "draft_all_replyable_messages": bool(
            getattr(profile, "draft_all_replyable_messages", False)
        ),
        "fallback_category": getattr(profile, "fallback_category", "") or "",
        "taxonomy": taxonomy,
        "ai_drafting": dict(sorted(
            (getattr(profile, "ai_drafting", {}) or {}).items()
        )),
        "category_sender_types": dict(sorted(
            (getattr(profile, "category_sender_types", {}) or {}).items()
        )),
        "system_labels": dict(sorted(
            (getattr(profile, "system_labels", {}) or {}).items()
        )),
        "protected_labels": sorted(
            getattr(profile, "protected_labels", ()) or ()
        ),
        "allow_protected_labels": bool(allow_protected_labels),
        "evidence_rules": evidence,
    }
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _parse_ai_drafting_approval(path):
    """Structurally validate a private generated-drafting approval artifact."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise DraftingConfigError("drafting approval must be an object")
    version = document.get("version")
    common = {
        "version", "account", "allow_protected_labels", "acknowledgement",
        # "_comment" only. Strictness is kept for every other unknown key so
        # a typo fails loudly instead of being silently ignored; this single
        # documented exception matches template-approval.example.json and
        # lets the shipped example explain itself in the file a reader is
        # actually looking at.
        "_comment",
    }
    if version == AI_DRAFTING_APPROVAL_VERSION:
        allowed = common | {"approved_categories"}
    elif version in {
        LEGACY_GLOBAL_DRAFTING_APPROVAL_VERSION,
        PREVIOUS_GLOBAL_DRAFTING_APPROVAL_VERSION,
        GLOBAL_DRAFTING_APPROVAL_VERSION,
    }:
        allowed = common | {
            "draft_all_replyable_messages", "policy_digest",
        }
    else:
        raise DraftingConfigError(
            "drafting approval must be a supported version 1, 2, 3, or 4 object"
        )
    unexpected = sorted(set(document) - allowed)
    if unexpected:
        raise DraftingConfigError(
            "unsupported drafting approval keys: " + ", ".join(unexpected)
        )
    account = str(document.get("account", "")).strip().lower()
    if not account or "@" not in account:
        raise DraftingConfigError(
            "drafting approval must name the Gmail account"
        )
    protected = document.get("allow_protected_labels", False)
    if not isinstance(protected, bool):
        raise DraftingConfigError(
            "allow_protected_labels must be true or false"
        )
    if version == AI_DRAFTING_APPROVAL_VERSION:
        categories = document.get("approved_categories")
        if not isinstance(categories, list) or not categories:
            raise DraftingConfigError(
                "drafting approval must list at least one approved category"
            )
        normalized = []
        for category in categories:
            if not isinstance(category, str) or not _SLUG.fullmatch(category):
                raise DraftingConfigError(
                    f"invalid drafting category {category!r}"
                )
            if category in normalized:
                raise DraftingConfigError(
                    f"duplicate drafting category {category!r}"
                )
            normalized.append(category)
        if document.get("acknowledgement") not in {
            AI_DRAFTING_ACKNOWLEDGEMENT,
            LEGACY_AI_DRAFTING_ACKNOWLEDGEMENT,
        }:
            raise DraftingConfigError(
                "drafting acknowledgement does not match the required text"
            )
        return account, frozenset(normalized), protected, False, ""

    if document.get("draft_all_replyable_messages") is not True:
        raise DraftingConfigError(
            "global drafting approval must explicitly enable all replyable messages"
        )
    digest = document.get("policy_digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise DraftingConfigError("global drafting policy digest is invalid")
    expected_acknowledgements = {
        LEGACY_GLOBAL_DRAFTING_APPROVAL_VERSION:
            {
                LEGACY_GLOBAL_DRAFTING_ACKNOWLEDGEMENT,
                ORIGINAL_GLOBAL_DRAFTING_ACKNOWLEDGEMENT,
            },
        PREVIOUS_GLOBAL_DRAFTING_APPROVAL_VERSION:
            {PREVIOUS_GLOBAL_DRAFTING_ACKNOWLEDGEMENT},
        GLOBAL_DRAFTING_APPROVAL_VERSION:
            {GLOBAL_DRAFTING_ACKNOWLEDGEMENT},
    }[version]
    if document.get("acknowledgement") not in expected_acknowledgements:
        raise DraftingConfigError(
            "global drafting acknowledgement does not match the required text"
        )
    return (
        account, frozenset(), protected, True, digest,
        version != LEGACY_GLOBAL_DRAFTING_APPROVAL_VERSION,
    )


def precheck_ai_drafting_approval(path):
    """Fail on malformed local JSON before any Gmail contact."""
    if path:
        _parse_ai_drafting_approval(path)


def load_ai_drafting_approval(path, actual_account, valid_categories,
                              profile=None):
    """Load and bind generated-drafting permission to the mailbox."""
    if not path:
        return AiDraftingApprovals(account=actual_account)
    parsed = _parse_ai_drafting_approval(path)
    if len(parsed) == 5:
        account, categories, protected, global_policy, digest = parsed
        include_bulk_messages = False
    else:
        account, categories, protected, global_policy, digest, \
            include_bulk_messages = parsed
    if account != (actual_account or "").strip().lower():
        raise DraftingConfigError(
            "drafting approval account does not match the authenticated "
            "Gmail account"
        )
    unknown = sorted(set(categories) - set(valid_categories))
    if unknown:
        raise DraftingConfigError(
            "drafting approval names categories outside the account "
            "taxonomy: " + ", ".join(unknown)
        )
    if global_policy:
        if profile is None:
            raise DraftingConfigError(
                "global drafting approval requires the loaded account profile"
            )
        if not getattr(profile, "draft_all_replyable_messages", False):
            raise DraftingConfigError(
                "global drafting approval cannot activate a disabled account policy"
            )
        expected = drafting_policy_digest(profile, protected)
        if digest != expected:
            raise DraftingConfigError(
                "global drafting approval no longer matches the account configuration"
            )
    return AiDraftingApprovals(
        account, categories, protected,
        draft_all_replyable_messages=global_policy,
        policy_digest=digest,
        include_bulk_messages=include_bulk_messages,
    )


def resolve_mode(profile, slug):
    """The drafting mode in force for one category.

    Fail-closed: an unrecognized mode resolves to ``off`` rather than to
    anything that drafts. A profile that declares no modes at all is one
    that does not use per-category drafting control (the code-defined legacy
    profile, or a hand-built test fixture); the config loader always
    populates a mode for every category, so no real account config can reach
    here ungoverned.
    """
    modes = getattr(profile, "drafting_modes", None) or {}
    if not modes:
        return None
    mode = modes.get(slug, MODE_OFF)
    if mode not in VALID_DRAFTING_MODES:
        return MODE_OFF
    return mode


def validate_drafting_modes(modes, categories, protected_categories=()):
    """Validate a whole drafting configuration at load time.

    Reject unknown modes. Protected-label permission is checked by the
    separate account-bound generated-drafting approval at runtime.
    """
    for slug, mode in sorted(modes.items()):
        if slug not in categories:
            raise DraftingConfigError(
                f"drafting configured for unknown category {slug!r}"
            )
        if mode not in VALID_DRAFTING_MODES:
            raise DraftingConfigError(
                f"category {slug!r} has unsupported drafting mode {mode!r}; "
                f"expected one of {sorted(VALID_DRAFTING_MODES)}"
            )
    return dict(modes)


def is_unreviewed_bulk(modes, protected_labels=()):
    """True for the shape that removes every review layer at once:
    every category free-form. ``protected_labels`` is accepted for backward
    compatibility but cannot make the risky shape disappear."""
    if not modes:
        return False
    return all(mode == MODE_GENERIC for mode in modes.values())


def expected_bulk_phrase(account, category_count):
    return UNSAFE_BULK_PHRASE_TEMPLATE.format(
        count=category_count, account=account
    )


def validate_bulk_acknowledgement(acknowledgement, account, category_count):
    """Check the config-side acknowledgement for the unreviewed-bulk shape.

    Bound to the account and the exact category count, so an acknowledgement
    cannot be copied between inboxes or survive the taxonomy growing.
    """
    if not isinstance(acknowledgement, dict):
        raise DraftingConfigError(
            "every category is set to free-form drafting with no protected "
            "label and no reviewed wording. This removes every review layer. "
            "Add an unreviewed_bulk_acknowledgement block to proceed."
        )
    ack_account = str(acknowledgement.get("account", "")).strip().lower()
    if ack_account != (account or "").strip().lower():
        raise DraftingConfigError(
            "unreviewed bulk acknowledgement names a different account"
        )
    if acknowledgement.get("category_count") != category_count:
        raise DraftingConfigError(
            "unreviewed bulk acknowledgement was written for a different "
            f"number of categories (says {acknowledgement.get('category_count')!r}, "
            f"found {category_count})"
        )
    phrase = str(acknowledgement.get("phrase", ""))
    expected = expected_bulk_phrase(account, category_count)
    if phrase != expected:
        raise DraftingConfigError(
            "unreviewed bulk acknowledgement phrase does not match exactly"
        )
    return True


def confirm_bulk_at_runtime(account, category_count, reader=input,
                            assume_yes=False):
    """Runtime gate for the unreviewed-bulk shape.

    ``assume_yes`` is accepted and deliberately ignored: --yes exists to skip
    routine prompts, not to skip the one confirmation that exists because a
    configuration removed every other safeguard.
    """
    expected = expected_bulk_phrase(account, category_count)
    print(
        "\nEvery category on this account is set to free-form generated drafting,\n"
        "with no protected label and no reviewed wording anywhere.\n"
        f"This will create unreviewed model-written drafts for all "
        f"{category_count} categories.\n"
    )
    print("To proceed, type this line exactly:")
    print(f"  {expected}")
    try:
        typed = reader("> ")
    except EOFError:
        print("No interactive input available; this gate cannot be scripted.")
        return False
    return typed.strip() == expected


def build_generic_body(model_text, max_words=None):
    """Return validated model-written wording as a ready-to-review body.

    The draft carries no machine-added preamble: the owner asked for drafts
    that read as finished replies. Every other guard in
    ``validate_generated_reply`` still applies, and the draft is still only
    ever created as an unsent Gmail draft.
    """
    clean = validate_generated_reply(model_text, max_words=max_words)
    return clean + "\n"


def build_safe_fallback_body(profile):
    """Return a fact-free acknowledgement after two rejected model attempts."""
    signature = str(
        (getattr(profile, "ai_drafting", {}) or {}).get("signature", "")
    ).strip()
    text = SAFE_FALLBACK_ACKNOWLEDGEMENT
    if signature:
        text += "\n\n" + signature
    return build_generic_body(text)


def validate_generated_reply(model_text, max_words=None):
    """Accept plain reply-body text only; reject empty or malformed output."""
    if not isinstance(model_text, str) or not model_text.strip():
        raise DraftingConfigError("draft generation returned no reply text")
    text = model_text.strip()
    if text.startswith("```") or text.endswith("```"):
        raise DraftingConfigError(
            "draft generation returned a code block instead of reply text"
        )
    if len(text) > MAX_GENERATED_REPLY_CHARS:
        raise DraftingConfigError(
            "draft generation exceeded the maximum reply length"
        )
    if max_words is not None:
        if not isinstance(max_words, int) or max_words <= 0:
            raise DraftingConfigError("draft word limit is invalid")
        if len(re.findall(r"\b\w+\b", text, re.UNICODE)) > max_words:
            raise DraftingConfigError(
                "draft generation exceeded the configured word limit"
            )
    if _HEADER_LINE.search(text):
        raise DraftingConfigError(
            "draft generation returned email headers instead of body text"
        )
    if _ACCOUNT_ACTION_CLAIM.search(text):
        raise DraftingConfigError(
            "draft generation claimed an account action"
        )
    if _INTERNAL_DISCLOSURE.search(text):
        raise DraftingConfigError(
            "draft generation attempted to expose internal or secret data"
        )
    if _SENSITIVE_DISCLOSURE.search(text):
        raise DraftingConfigError(
            "draft generation attempted to repeat sensitive data"
        )
    return text
