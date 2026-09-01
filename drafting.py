"""Per-category drafting opt-in: off / template / generic.

Drafting is off for every category until the account owner turns it on for
that specific category, and then must choose how:

  * ``template`` - the owner supplies wording, which passes the existing
    wording-bound, account-bound template approval gate unchanged.
  * ``generic``  - free-form model-written replies for that category only.
    Every such draft carries a fixed banner declaring it AI-drafted and
    unreviewed. Generic mode never depends on a wording-bound template.

Generic drafting has its own account-bound approval artifact. It approves
categories, not exact wording, so an owner can edit AI guidance or edit each
Gmail draft without regenerating template digests. Protected-label messages
need an additional boolean acknowledgement in that artifact. This keeps the
year-label evidence gate separate from the decision to prepare an unsent AI
reply.

The banner is a code constant, never config. A config-supplied banner could
be set to the empty string, which is precisely the failure the banner exists
to prevent.
"""
import json
import os
import re

MODE_OFF = "off"
MODE_TEMPLATE = "template"
MODE_GENERIC = "generic"
VALID_DRAFTING_MODES = frozenset({MODE_OFF, MODE_TEMPLATE, MODE_GENERIC})

# Not configurable. See module docstring.
AI_BANNER = (
    "-------------------------------------------------\n"
    "AI-DRAFTED - UNREVIEWED WORDING - NOT SENT\n"
    "No human has read this text. Delete this banner and\n"
    "edit before sending, or discard.\n"
    "-------------------------------------------------\n\n"
)

AI_DRAFTING_APPROVAL_VERSION = 1
AI_DRAFTING_ACKNOWLEDGEMENT = (
    "I approve AI-generated unsent drafts for the listed categories and "
    "understand that every draft must be reviewed before sending."
)
_SLUG = re.compile(r"^[a-z][a-z0-9_]*$")

MAX_GENERATED_REPLY_CHARS = 12_000

UNSAFE_BULK_PHRASE_TEMPLATE = (
    "I approve unreviewed AI drafting for all {count} categories on {account}"
)


class DraftingConfigError(ValueError):
    """Raised for a drafting configuration that cannot be safely honored."""


class AiDraftingApprovals:
    """Account-bound permission to generate unsent AI drafts.

    Unlike template approval, this deliberately does not bind exact wording:
    generated text changes for every email. The stable permission boundary is
    the configured category set and whether protected-label messages may also
    receive an AI draft.
    """

    def __init__(self, account="", categories=(), allow_protected_labels=False):
        self.account = (account or "").strip().lower()
        self.categories = frozenset(categories or ())
        self.allow_protected_labels = bool(allow_protected_labels)

    def check(self, category, carries_protected_label=False):
        if category not in self.categories:
            return False, (
                f"AI drafting is not approved for category {category!r}; "
                "not drafting"
            )
        if carries_protected_label and not self.allow_protected_labels:
            return False, (
                "AI drafting approval does not include protected-label "
                "messages; not drafting"
            )
        return True, ""

    def describe(self):
        if not self.categories:
            return "none (AI-generated draft creation is blocked)"
        suffix = (
            "; protected-label messages approved"
            if self.allow_protected_labels
            else "; protected-label messages blocked"
        )
        return ", ".join(sorted(self.categories)) + suffix


def _parse_ai_drafting_approval(path):
    """Structurally validate a private AI-drafting approval artifact."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise DraftingConfigError("AI drafting approval must be an object")
    allowed = {
        "version", "account", "approved_categories",
        "allow_protected_labels", "acknowledgement",
        # "_comment" only. Strictness is kept for every other unknown key so
        # a typo fails loudly instead of being silently ignored; this single
        # documented exception matches template-approval.example.json and
        # lets the shipped example explain itself in the file a reader is
        # actually looking at.
        "_comment",
    }
    unexpected = sorted(set(document) - allowed)
    if unexpected:
        raise DraftingConfigError(
            "unsupported AI drafting approval keys: " + ", ".join(unexpected)
        )
    if document.get("version") != AI_DRAFTING_APPROVAL_VERSION:
        raise DraftingConfigError(
            "AI drafting approval must be a version 1 object"
        )
    account = str(document.get("account", "")).strip().lower()
    if not account or "@" not in account:
        raise DraftingConfigError(
            "AI drafting approval must name the Gmail account"
        )
    categories = document.get("approved_categories")
    if not isinstance(categories, list) or not categories:
        raise DraftingConfigError(
            "AI drafting approval must list at least one approved category"
        )
    normalized = []
    for category in categories:
        if not isinstance(category, str) or not _SLUG.fullmatch(category):
            raise DraftingConfigError(
                f"invalid AI drafting category {category!r}"
            )
        if category in normalized:
            raise DraftingConfigError(
                f"duplicate AI drafting category {category!r}"
            )
        normalized.append(category)
    protected = document.get("allow_protected_labels", False)
    if not isinstance(protected, bool):
        raise DraftingConfigError(
            "allow_protected_labels must be true or false"
        )
    if document.get("acknowledgement") != AI_DRAFTING_ACKNOWLEDGEMENT:
        raise DraftingConfigError(
            "AI drafting acknowledgement does not match the required text"
        )
    return account, frozenset(normalized), protected


def precheck_ai_drafting_approval(path):
    """Fail on malformed local JSON before any Gmail contact."""
    if path:
        _parse_ai_drafting_approval(path)


def load_ai_drafting_approval(path, actual_account, valid_categories):
    """Load and bind AI-drafting permission to the authenticated mailbox."""
    if not path:
        return AiDraftingApprovals(account=actual_account)
    account, categories, protected = _parse_ai_drafting_approval(path)
    if account != (actual_account or "").strip().lower():
        raise DraftingConfigError(
            "AI drafting approval account does not match the authenticated "
            "Gmail account"
        )
    unknown = sorted(set(categories) - set(valid_categories))
    if unknown:
        raise DraftingConfigError(
            "AI drafting approval names categories outside the account "
            "taxonomy: " + ", ".join(unknown)
        )
    return AiDraftingApprovals(account, categories, protected)


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
    separate account-bound AI-drafting approval at runtime.
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
        "\nEvery category on this account is set to free-form AI drafting,\n"
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


def build_generic_body(model_text):
    """Prefix model-written wording with the non-negotiable banner."""
    clean = validate_generated_reply(model_text)
    return AI_BANNER + clean + "\n"


def validate_generated_reply(model_text):
    """Accept plain reply-body text only; reject empty or malformed output."""
    if not isinstance(model_text, str) or not model_text.strip():
        raise DraftingConfigError("AI draft generation returned no reply text")
    text = model_text.strip()
    if text.startswith("```") or text.endswith("```"):
        raise DraftingConfigError(
            "AI draft generation returned a code block instead of reply text"
        )
    if len(text) > MAX_GENERATED_REPLY_CHARS:
        raise DraftingConfigError(
            "AI draft generation exceeded the maximum reply length"
        )
    first = text.splitlines()[0].strip().casefold()
    if first.startswith(("to:", "from:", "subject:", "cc:", "bcc:")):
        raise DraftingConfigError(
            "AI draft generation returned email headers instead of body text"
        )
    if carries_banner(text):
        raise DraftingConfigError(
            "AI draft generation attempted to reproduce the safety banner"
        )
    return text


def carries_banner(body):
    return AI_BANNER.strip().splitlines()[1] in (body or "")
