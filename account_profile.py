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

DECISION RECORD:
  * Migration must NOT auto-confirm an existing account's categories. the account owner's
    seven categories get the same fresh confirmation prompt as any discovered
    taxonomy, even though he has used those names all season. Confirmation
    attests that a human reviewed the taxonomy now; inheriting it from history
    would make "nothing drafts until confirmed" untrue for the one account
    most likely to draft first.
  * Generic drafting never requires exact template wording. It is separately
    approved by account and category, and protected-label messages require an
    explicit acknowledgement in that approval artifact.
  * The separate AI-drafting approval is the durable acknowledgement for
    generic categories. It is account/category-bound and works unattended.
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
    system_labels: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )

    # Evidence-gated labelling (generalizes the 2027B gate)
    evidence_categories: frozenset = frozenset()
    evidence_sender_types: frozenset = frozenset()
    supported_years: frozenset = frozenset()
    # The value the evidence gate expects the model and the message text to
    # agree on before an evidence-gated label may be applied.
    evidence_expected_value: str = ""
    evidence_rules: tuple = ()
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
    drafting_guidance: MappingProxyType = field(
        default_factory=lambda: MappingProxyType({})
    )
    ai_drafting: MappingProxyType = field(
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
    system_labels=MappingProxyType({
        "needs_review": "Example/Triage/Needs Review",
        "processed": "Example/Triage/Processed",
    }),
    evidence_categories=frozenset({
        "recruit_intro", "recruit_update", "video_update",
    }),
    evidence_sender_types=frozenset({"recruit"}),
    supported_years=frozenset({"2026", "2027", "2028", "2029", "2030"}),
    evidence_expected_value="2027",
    evidence_rules=({
        "label": "2027B",
        "expected_value": "2027",
        "require_sender_type": frozenset({"recruit"}),
        "require_categories": frozenset({
            "recruit_intro", "recruit_update", "video_update",
        }),
        "min_confidence": "high",
    },),
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
        "evidence_gated_labels", "system_labels", "ai_drafting", "paths",
        "unreviewed_bulk_acknowledgement",
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
    guidance = {}
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
            expected_sender = str(raw["expected_sender"]).strip().lower()
            _require(expected_sender in VALID_SENDER_TYPES,
                     f"unsupported expected_sender for {slug!r}")
            sender_types[slug] = expected_sender
        # Absent drafting config means off. Every category gets an explicit
        # mode, so no loaded config can reach the runtime ungoverned.
        drafting = raw.get("drafting") or {}
        _require(isinstance(drafting, dict),
                 f"drafting for {slug!r} must be an object")
        unexpected_drafting = sorted(set(drafting) - {"mode", "guidance"})
        _require(not unexpected_drafting,
                 f"unsupported drafting keys for {slug!r}: "
                 + ", ".join(unexpected_drafting))
        modes[slug] = str(drafting.get("mode", drafting_module.MODE_OFF))
        category_guidance = str(drafting.get("guidance", "")).strip()
        _require(len(category_guidance) <= 2_000,
                 f"drafting guidance for {slug!r} is too long")
        if category_guidance:
            guidance[slug] = category_guidance
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

    raw_evidence = document.get("evidence_gated_labels") or []
    _require(isinstance(raw_evidence, list),
             "evidence_gated_labels must be a list")
    evidence_rules = []
    year_labels = {}
    evidence_categories = set()
    evidence_sender_types = set()
    for raw in raw_evidence:
        _require(isinstance(raw, dict),
                 "each evidence-gated label must be an object")
        allowed_rule = {
            "label", "pattern_set", "classifier_field", "expected_value",
            "require_sender_type", "require_categories", "min_confidence",
        }
        unexpected_rule = sorted(set(raw) - allowed_rule)
        _require(not unexpected_rule,
                 "unsupported evidence gate keys: "
                 + ", ".join(unexpected_rule))
        label = raw.get("label")
        taxonomy_module.validate_label_name(label)
        _require(raw.get("pattern_set") == "grad_year",
                 "only the grad_year evidence pattern set is supported")
        _require(raw.get("classifier_field") == "grad_year",
                 "only the grad_year classifier field is supported")
        expected = str(raw.get("expected_value", "")).strip()
        _require(len(expected) == 4 and expected.isdigit()
                 and expected.startswith("20"),
                 "evidence expected_value must be a four-digit year")
        _require(expected not in year_labels,
                 f"duplicate evidence rule for year {expected}")
        required_senders = raw.get("require_sender_type") or []
        required_categories = raw.get("require_categories") or []
        _require(isinstance(required_senders, list) and required_senders,
                 "evidence rule must require at least one sender type")
        _require(isinstance(required_categories, list) and required_categories,
                 "evidence rule must require at least one category")
        required_senders = {
            str(value).strip().lower() for value in required_senders
        }
        required_categories = {
            str(value).strip().lower() for value in required_categories
        }
        _require(required_senders <= VALID_SENDER_TYPES,
                 "evidence rule contains an unsupported sender type")
        _require(required_categories <= slugs,
                 "evidence rule contains a category outside the taxonomy")
        _require(raw.get("min_confidence", "high") == "high",
                 "evidence-gated labels require high confidence")
        year_labels[expected] = label
        evidence_categories.update(required_categories)
        evidence_sender_types.update(required_senders)
        evidence_rules.append({
            "label": label,
            "expected_value": expected,
            "require_sender_type": frozenset(required_senders),
            "require_categories": frozenset(required_categories),
            "min_confidence": "high",
        })

    raw_system = document.get("system_labels") or {}
    _require(isinstance(raw_system, dict), "system_labels must be an object")
    unexpected_system = sorted(set(raw_system) - SYSTEM_LABEL_KEYS)
    _require(not unexpected_system,
             "unsupported system label keys: " + ", ".join(unexpected_system))
    system_labels = {}
    for key, name in raw_system.items():
        taxonomy_module.validate_label_name(name)
        system_labels[key] = name
    if system_labels:
        _require(set(system_labels) == SYSTEM_LABEL_KEYS,
                 "system_labels must define needs_review and processed")

    raw_ai = document.get("ai_drafting") or {}
    _require(isinstance(raw_ai, dict), "ai_drafting must be an object")
    allowed_ai = {
        "display_name", "role", "organization", "signature",
        "default_guidance", "max_words",
    }
    unexpected_ai = sorted(set(raw_ai) - allowed_ai)
    _require(not unexpected_ai,
             "unsupported ai_drafting keys: " + ", ".join(unexpected_ai))
    ai_drafting = {}
    for key in allowed_ai - {"max_words"}:
        value = str(raw_ai.get(key, "")).strip()
        _require(len(value) <= 2_000,
                 f"ai_drafting {key!r} is too long")
        if value:
            ai_drafting[key] = value
    max_words = raw_ai.get("max_words", 180)
    _require(isinstance(max_words, int) and 30 <= max_words <= 500,
             "ai_drafting max_words must be an integer from 30 to 500")
    ai_drafting["max_words"] = max_words

    # Retained as explicit context for drafting-mode validation. Runtime AI
    # approval decides whether protected-label messages may be drafted.
    protected_categories = {
        slug for slug, label in labels.items() if label in protected_names
    }
    modes = drafting_module.validate_drafting_modes(
        modes, slugs, protected_categories
    )

    acknowledgement = document.get("unreviewed_bulk_acknowledgement")
    # Backward compatibility for configs created before the dedicated
    # AI-drafting approval existed. New configs do not need this duplicate
    # acknowledgement; runtime drafting still fails closed without the new
    # account/category-bound artifact.
    if acknowledgement is not None:
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
        year_labels=MappingProxyType(year_labels),
        category_labels=MappingProxyType(labels),
        system_labels=MappingProxyType(system_labels),
        evidence_categories=frozenset(evidence_categories),
        evidence_sender_types=frozenset(evidence_sender_types),
        supported_years=frozenset(year_labels),
        evidence_expected_value=(
            next(iter(year_labels)) if len(year_labels) == 1 else ""
        ),
        evidence_rules=tuple(evidence_rules),
        taxonomy=tuple(entries),
        drafting_modes=MappingProxyType(modes),
        drafting_guidance=MappingProxyType(guidance),
        ai_drafting=MappingProxyType(ai_drafting),
        unreviewed_bulk_acknowledgement=acknowledgement,
        state_dir=str(paths.get("state_dir", "triage-state")),
        draft_log_dir=str(paths.get("draft_log_dir", "draft-logs")),
        template_dir=str(paths.get("template_dir", "templates")),
    )
