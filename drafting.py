"""Per-category drafting opt-in: off / template / generic.

Drafting is off for every category until the account owner turns it on for
that specific category, and then must choose how:

  * ``template`` - the owner supplies wording, which passes the existing
    wording-bound, account-bound template approval gate unchanged.
  * ``generic``  - free-form model-written replies for that category only.
    Every such draft carries a fixed banner declaring it AI-drafted and
    unreviewed.

Two refusals are structural rather than configurable:

  1. ``generic`` is refused outright for any category carrying a protected
     label. Model-authored wording plus a label that exists because it needs
     extra care is a contradiction, so it is rejected rather than gated.
  2. The all-generic / no-protection / nothing-reviewed shape removes every
     review layer at once. It requires a config acknowledgement naming the
     account and category count, plus a runtime typed phrase containing the
     account address, which --yes cannot bypass.

The banner is a code constant, never config. A config-supplied banner could
be set to the empty string, which is precisely the failure the banner exists
to prevent.
"""
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

UNSAFE_BULK_PHRASE_TEMPLATE = (
    "I approve unreviewed AI drafting for all {count} categories on {account}"
)


class DraftingConfigError(ValueError):
    """Raised for a drafting configuration that cannot be safely honored."""


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

    Rejects unknown modes and the generic/protected-label combination.
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
        if mode == MODE_GENERIC and slug in protected_categories:
            raise DraftingConfigError(
                f"category {slug!r} carries a protected label; free-form "
                "drafting is refused for protected categories"
            )
    return dict(modes)


def is_unreviewed_bulk(modes, protected_labels=()):
    """True for the shape that removes every review layer at once:
    every category free-form, and no protected label anywhere."""
    if not modes:
        return False
    if protected_labels:
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
    return AI_BANNER + (model_text or "").strip() + "\n"


def carries_banner(body):
    return AI_BANNER.strip().splitlines()[1] in (body or "")
