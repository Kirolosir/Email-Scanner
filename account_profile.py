"""The one place a category name, label name, account address, grad year, or
timezone may appear as a literal in production source.

Pass one of the multi-inbox generalization. Every other production module
sources these values from here instead of defining its own copy, so the
inventory of 24 hardcoded sites across 6 modules collapses to this file.
That makes the eventual per-account config a matter of loading a different
profile, not of hunting literals again.

This pass is deliberately behavior-neutral. ``LEGACY_PROFILE`` reproduces the
exact values the tool used before the refactor, and ``load_profile(None)``
returns it, so nothing changes for the existing account until a real config
file is supplied.

Structural vocabulary is NOT domain data and stays in code: confidence levels,
the ``unknown`` sentinel, sender-type kinds, and the ``administrative`` system
category used for deterministically-detected automated mail. Those are protocol
values the code reasons about, not per-inbox choices.

DECISION RECORD (pass two, do not lose):
  * Migration must NOT auto-confirm an existing account's categories. the account owner's
    seven categories get the same fresh confirmation prompt as any discovered
    taxonomy, even though he has used those names all season. Confirmation
    attests that a human reviewed the taxonomy now; inheriting it from history
    would make "nothing drafts until confirmed" untrue for the one account
    most likely to draft first.
  * Generic (free-form) drafting is refused outright for any category carrying
    a protected label, rather than gated. Model-authored wording plus a label
    that exists because it needs extra care is a contradiction.
  * The all-generic/no-protection configuration requires a config
    acknowledgement block naming the account and category count, plus a runtime
    typed phrase containing the account address, which --yes cannot bypass.
"""
from dataclasses import dataclass, field
from types import MappingProxyType

# ---------------------------------------------------------------------
# Structural vocabulary - protocol values, not per-inbox domain data.
# ---------------------------------------------------------------------
UNKNOWN = "unknown"
SYSTEM_CATEGORY_ADMINISTRATIVE = "administrative"
VALID_CONFIDENCE = frozenset({"high", "medium", "low"})
VALID_SENDER_TYPES = frozenset({
    "recruit", "parent", "coach", "administrative", "other", UNKNOWN,
})
SYSTEM_LABEL_KEYS = frozenset({"needs_review", "processed"})


@dataclass(frozen=True)
class AccountProfile:
    """Everything about one inbox that used to be a module-level constant.

    Frozen so a caller cannot mutate shared state, and so the "one place
    literals live" property cannot be defeated at runtime.
    """

    # Identity
    account: str = ""
    timezone: str = "UTC"

    # Taxonomy
    categories: frozenset = frozenset()
    category_sender_types: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )

    # Labels
    protected_labels: frozenset = frozenset()
    year_labels: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )
    category_labels: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )

    # Evidence-gated labelling (generalizes the 2027B gate)
    evidence_categories: frozenset = frozenset()
    evidence_sender_types: frozenset = frozenset()
    supported_years: frozenset = frozenset()
    # The value the evidence gate expects the model and the message text to
    # agree on before an evidence-gated label may be applied.
    evidence_expected_value: str = ""
    # Categories the campaign audit treats as non-recruit correspondence.
    non_recruit_audit_categories: frozenset = frozenset()

    # Discovered taxonomy, or None for a code-defined profile. The
    # confirmation gate applies only when a discovered taxonomy is present:
    # LEGACY_PROFILE's categories are code constants that went through code
    # review, not model proposals, so there is nothing for an owner to
    # confirm. A migrated config always carries a taxonomy with confirmation
    # absent, so migration does not inherit approval from history.
    taxonomy: tuple = ()
    # slug -> "off" | "template" | "generic". Empty means the profile does
    # not use per-category drafting control; the loader always populates it.
    drafting_modes: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )
    unreviewed_bulk_acknowledgement: object = None

    # Private per-account paths
    state_dir: str = "triage-state"
    draft_log_dir: str = "draft-logs"
    template_dir: str = "templates"

    @property
    def valid_categories(self):
        """Category slugs plus the unknown sentinel, which is always valid."""
        return frozenset(self.categories) | {UNKNOWN}

    @property
    def state_path(self):
        return f"{self.state_dir}/daily-state.json"

    @property
    def status_path(self):
        return f"{self.state_dir}/daily-status.json"

    @property
    def lock_dir(self):
        return f"{self.state_dir}/locks"


# ---------------------------------------------------------------------
# LEGACY_PROFILE - the pre-refactor values, reproduced exactly.
#
# This is the only production location where these literals appear. It is
# what load_profile() returns when no per-account config is supplied, which
# is what keeps pass one behavior-neutral.
# ---------------------------------------------------------------------
_LEGACY_CATEGORIES = frozenset({
    "recruit_intro", "recruit_update", "video_update", "parent",
    "other_coach", "camp_inquiry", "administrative", "other",
})

_LEGACY_CATEGORY_SENDER_TYPES = MappingProxyType({
    "recruit_intro": "recruit",
    "recruit_update": "recruit",
    "video_update": "recruit",
    "parent": "parent",
    "other_coach": "coach",
    "administrative": "administrative",
})

_LEGACY_YEAR_LABELS = MappingProxyType({
    "2026": "Recruits/2026",
    "2027": "Recruits/2027",
    "2028": "Recruits/2028",
    "2029": "Recruits/2029",
    "2030": "Recruits/2030",
})

_LEGACY_CATEGORY_LABELS = MappingProxyType({
    "recruit_intro": "Triage/Recruit Intro",
    "recruit_update": "Triage/Recruit Update",
    "parent": "Triage/Parent",
    "camp_inquiry": "Triage/Camp Inquiry",
    "other": "Triage/Other",
})

LEGACY_PROFILE = AccountProfile(
    account="",
    timezone="America/New_York",
    categories=_LEGACY_CATEGORIES,
    category_sender_types=_LEGACY_CATEGORY_SENDER_TYPES,
    protected_labels=frozenset({"2027B"}),
    year_labels=_LEGACY_YEAR_LABELS,
    category_labels=_LEGACY_CATEGORY_LABELS,
    evidence_categories=frozenset({
        "recruit_intro", "recruit_update", "video_update",
    }),
    evidence_sender_types=frozenset({"recruit"}),
    supported_years=frozenset({"2026", "2027", "2028", "2029", "2030"}),
    evidence_expected_value="2027",
    non_recruit_audit_categories=frozenset({
        "parent", "other_coach", "administrative",
    }),
)

# The label a reviewed 2027 mapping must resolve to for this profile. Kept
# here rather than asserted as a literal inside triage_config, which is what
# made that validator single-tenant.
LEGACY_REVIEWED_YEAR_LABEL = ("2027", "2027B")


ACCOUNT_CONFIG_VERSION = 1


def load_profile(path=None):
    """Return the account profile to operate under.

    ``None`` yields LEGACY_PROFILE, preserving the pre-generalization
    behavior for the existing account until it migrates.
    """
    if path is None:
        return LEGACY_PROFILE
    return _load_account_config(path)


def assert_profile_matches_account(profile, actual_account):
    """Bind a loaded account config to the authenticated mailbox.

    Mirrors the campaign, template, and taxonomy artifacts: a config written
    for one inbox must not drive another. The legacy profile declares no
    account and is exempt, since it is the pre-migration default rather than
    a per-account artifact.

    ``actual_account`` is required so the binding cannot be skipped by
    omitting an argument.
    """
    declared = (getattr(profile, "account", "") or "").strip().lower()
    if not declared:
        return profile
    if declared != (actual_account or "").strip().lower():
        raise ValueError(
            "account config describes a different Gmail account than the "
            "one authenticated"
        )
    return profile


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _load_account_config(path):
    """Parse and strictly validate one per-account config file.

    Unknown keys are rejected rather than ignored, so a typo cannot silently
    leave a safety setting at its default.
    """
    import json

    import drafting as drafting_module
    import taxonomy as taxonomy_module

    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)

    _require(isinstance(document, dict), "account config must be an object")
    _require(document.get("version") == ACCOUNT_CONFIG_VERSION,
             "account config must be a version 1 object")

    allowed = {
        "version", "account", "timezone", "taxonomy", "protected_labels",
        "evidence_gated_labels", "paths", "unreviewed_bulk_acknowledgement",
    }
    unexpected = sorted(set(document) - allowed)
    _require(not unexpected,
             f"unsupported account config keys: {', '.join(unexpected)}")

    account = str(document.get("account", "")).strip().lower()
    _require(account and "@" in account,
             "account config must name the Gmail account it describes")

    timezone = str(document.get("timezone", "")).strip()
    _require(timezone, "account config must name a timezone")

    raw_taxonomy = document.get("taxonomy") or []
    _require(isinstance(raw_taxonomy, list),
             "account config taxonomy must be a list")
    entries = []
    slugs = set()
    labels = {}
    sender_types = {}
    modes = {}
    for raw in raw_taxonomy:
        _require(isinstance(raw, dict), "each taxonomy entry must be an object")
        slug = taxonomy_module.sanitize_slug(raw.get("slug", ""))
        _require(slug not in slugs, f"duplicate category slug {slug!r}")
        slugs.add(slug)
        label = raw.get("label")
        if label is not None:
            taxonomy_module.validate_label_name(label)
            labels[slug] = label
        if raw.get("expected_sender"):
            sender_types[slug] = str(raw["expected_sender"]).strip().lower()
        # Absent drafting config means off. Every category gets an explicit
        # mode, so no loaded config can reach the runtime ungoverned.
        drafting = raw.get("drafting") or {}
        _require(isinstance(drafting, dict),
                 f"drafting for {slug!r} must be an object")
        modes[slug] = str(drafting.get("mode", drafting_module.MODE_OFF))
        entries.append({
            "slug": slug,
            "display": str(raw.get("display", slug)),
            "description": str(raw.get("description", "")),
            "examples": list(raw.get("examples", ())),
            "label": label,
            "digest": taxonomy_module.proposal_digest(
                slug, raw.get("description", ""), raw.get("examples", ())
            ),
        })
    _require(entries, "account config taxonomy must not be empty")

    protected = document.get("protected_labels") or []
    _require(isinstance(protected, list),
             "protected_labels must be a list")
    protected_names = set()
    for entry in protected:
        name = entry.get("label") if isinstance(entry, dict) else entry
        taxonomy_module.validate_label_name(name)
        protected_names.add(name)

    # Categories whose label is protected: generic drafting is refused there.
    protected_categories = {
        slug for slug, label in labels.items() if label in protected_names
    }
    modes = drafting_module.validate_drafting_modes(
        modes, slugs, protected_categories
    )

    acknowledgement = document.get("unreviewed_bulk_acknowledgement")
    if drafting_module.is_unreviewed_bulk(modes, protected_names):
        drafting_module.validate_bulk_acknowledgement(
            acknowledgement, account, len(modes)
        )

    paths = document.get("paths") or {}
    _require(isinstance(paths, dict), "paths must be an object")

    return AccountProfile(
        account=account,
        timezone=timezone,
        categories=frozenset(slugs),
        category_sender_types=MappingProxyType(sender_types),
        protected_labels=frozenset(protected_names),
        year_labels=MappingProxyType({}),
        category_labels=MappingProxyType(labels),
        taxonomy=tuple(entries),
        drafting_modes=MappingProxyType(modes),
        unreviewed_bulk_acknowledgement=acknowledgement,
        state_dir=str(paths.get("state_dir", "triage-state")),
        draft_log_dir=str(paths.get("draft_log_dir", "draft-logs")),
        template_dir=str(paths.get("template_dir", "templates")),
    )
