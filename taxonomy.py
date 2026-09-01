"""Discovered taxonomy: proposal, sanitization, and per-category confirmation.

This module is the boundary where model output stops being text and becomes
structured data the rest of the tool may act on. Before this pass,
triage_config.py could promise that "model text can never become a Gmail label
name" because every name was a code constant. Taxonomy discovery inverts that,
so containment moves here:

  * Discovery never calls the Gmail API. It writes proposals to a review file.
    Label creation stays exclusively in setup_labels.py behind its typed
    confirmation.
  * Every proposed name passes sanitize_slug / validate_label_name before it
    is stored, so an injected or malformed name cannot reach Gmail.
  * The slug is the stable identity. Display names may be edited freely; a
    cosmetic rename cannot silently re-point a drafting setting.
  * Confirmation is per category and bound to the digest of exactly what the
    owner was shown, and to the account. Redefining a category voids its
    confirmation; confirming one category never confirms another.

Labeling is deliberately NOT gated on confirmation - organizing an inbox
carries no reply risk, and the labeling log is what gives the owner the
information the confirmation step exists to review. Drafting is gated.
"""
import hashlib
import json
import os
import re
import unicodedata

# Gmail rejects or reserves these; a proposal matching one is refused rather
# than silently renamed, so the owner sees the collision.
RESERVED_LABEL_NAMES = frozenset({
    "INBOX", "SENT", "TRASH", "SPAM", "DRAFT", "DRAFTS", "STARRED",
    "IMPORTANT", "UNREAD", "READ", "CHAT", "ALL MAIL", "ALLMAIL",
})
RESERVED_LABEL_PREFIXES = ("CATEGORY_",)

MAX_LABEL_LENGTH = 225          # Gmail's documented per-label maximum
MAX_SLUG_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 300
MAX_EXAMPLES = 5

SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
# Label segments: printable, no control characters, no leading/trailing space.
LABEL_SEGMENT = re.compile(r"^[^\x00-\x1f\x7f/]+$")

TAXONOMY_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
TAXONOMY_VERSION = 1


class TaxonomyError(ValueError):
    """Raised for any malformed or unsafe taxonomy input."""


def sanitize_slug(raw):
    """Turn a model-proposed category name into a safe identifier.

    Returns a slug matching SLUG_PATTERN. Raises TaxonomyError when nothing
    usable survives, rather than inventing a fallback name - a silently
    renamed category is one the owner did not review.
    """
    if not isinstance(raw, str):
        raise TaxonomyError("category name must be a string")
    # Strip accents and non-ASCII so the slug is stable and comparable.
    folded = unicodedata.normalize("NFKD", raw)
    folded = folded.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "_", folded.strip().lower()).strip("_")
    slug = re.sub(r"_{2,}", "_", slug)
    if not slug:
        raise TaxonomyError(f"category name {raw!r} yields no usable slug")
    if slug[0].isdigit():
        slug = f"c_{slug}"
    slug = slug[:MAX_SLUG_LENGTH].rstrip("_")
    if not SLUG_PATTERN.match(slug):
        raise TaxonomyError(f"category name {raw!r} yields an invalid slug")
    return slug


def validate_label_name(name, existing_labels=()):
    """Validate a proposed Gmail label name from model output.

    Refuses reserved names, control characters, empty or whitespace-padded
    segments, over-length names, and collisions with labels that already
    exist. A collision is an error, not a silent reuse: writing into a label
    the owner already uses for something else is exactly the failure this
    boundary exists to prevent.
    """
    if not isinstance(name, str) or not name.strip():
        raise TaxonomyError("label name must be a non-empty string")
    if name != name.strip():
        raise TaxonomyError(f"label name {name!r} has leading/trailing space")
    if len(name) > MAX_LABEL_LENGTH:
        raise TaxonomyError(
            f"label name exceeds {MAX_LABEL_LENGTH} characters"
        )

    segments = name.split("/")
    if any(segment != segment.strip() or not segment for segment in segments):
        raise TaxonomyError(
            f"label name {name!r} has an empty or padded path segment"
        )
    for segment in segments:
        if not LABEL_SEGMENT.match(segment):
            raise TaxonomyError(
                f"label name {name!r} contains a control character"
            )

    # One check, not two: every reserved name is also a segment, so a
    # separate top-level test would be dead code that masks mutations.
    for segment in segments:
        upper = segment.upper()
        if upper in RESERVED_LABEL_NAMES:
            raise TaxonomyError(
                f"label name {name!r} uses the reserved Gmail name "
                f"{segment!r}"
            )
        if any(upper.startswith(prefix) for prefix in RESERVED_LABEL_PREFIXES):
            raise TaxonomyError(
                f"label name {name!r} uses a reserved prefix"
            )

    for existing in existing_labels:
        if existing.casefold() == name.casefold():
            raise TaxonomyError(
                f"label name {name!r} already exists in this account; "
                "review the collision rather than reusing it"
            )
    return name


def proposal_digest(slug, description, examples):
    """Digest of exactly what the owner is shown for one category.

    Confirmation binds to this. Changing the description or the example
    subjects changes the digest and voids the confirmation, because the owner
    approved a category as presented, not a name in isolation.
    """
    payload = json.dumps(
        {
            "slug": slug,
            "description": description or "",
            "examples": list(examples or ()),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_proposal(raw_name, description="", examples=(), label=None,
                   existing_labels=()):
    """Turn one raw model proposal into a validated, digest-bearing record."""
    slug = sanitize_slug(raw_name)
    description = (description or "").strip()[:MAX_DESCRIPTION_LENGTH]
    clean_examples = [
        str(example).strip()[:200]
        for example in list(examples or ())[:MAX_EXAMPLES]
        if str(example).strip()
    ]
    if label is not None:
        validate_label_name(label, existing_labels)
    return {
        "slug": slug,
        "display": str(raw_name).strip()[:MAX_SLUG_LENGTH * 2],
        "description": description,
        "examples": clean_examples,
        "label": label,
        "digest": proposal_digest(slug, description, clean_examples),
    }


def build_taxonomy(raw_proposals, existing_labels=()):
    """Validate a full set of proposals. Duplicate slugs are refused."""
    taxonomy = []
    seen = set()
    for raw in raw_proposals:
        if not isinstance(raw, dict):
            raise TaxonomyError("each proposal must be an object")
        proposal = build_proposal(
            raw.get("name", raw.get("slug", "")),
            raw.get("description", ""),
            raw.get("examples", ()),
            raw.get("label"),
            existing_labels,
        )
        if proposal["slug"] in seen:
            raise TaxonomyError(
                f"duplicate category slug {proposal['slug']!r} in proposals"
            )
        seen.add(proposal["slug"])
        taxonomy.append(proposal)
    if not taxonomy:
        raise TaxonomyError("taxonomy must contain at least one category")
    return taxonomy


# ---------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------

class TaxonomyConfirmation:
    """Which categories a human confirmed, bound to digest and account.

    An empty instance confirms nothing, so the default is fail-closed.
    """

    def __init__(self, account="", confirmed=None):
        self.account = (account or "").strip().lower()
        self.confirmed = dict(confirmed or {})

    def check(self, slug, digest):
        """Return ``(confirmed, reason)`` for one category."""
        expected = self.confirmed.get(slug)
        if expected is None:
            return False, (
                f"taxonomy unconfirmed: category {slug!r} has not been "
                "reviewed by the account owner"
            )
        if expected.lower() != (digest or "").lower():
            return False, (
                f"taxonomy unconfirmed: category {slug!r} changed since it "
                "was reviewed; re-confirmation required"
            )
        return True, ""

    def confirmed_slugs(self):
        return sorted(self.confirmed)

    def describe(self):
        if not self.confirmed:
            return "none (no category confirmed; drafting is blocked)"
        return ", ".join(sorted(self.confirmed))


def load_taxonomy_confirmation(path, actual_account):
    """Load a private, human-reviewed taxonomy confirmation artifact.

    Bound to the authenticated account, mirroring the campaign and template
    approval artifacts. ``actual_account`` is required so the binding cannot
    be skipped by omitting an argument.
    """
    if not path:
        return TaxonomyConfirmation(account=actual_account)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)

    if not isinstance(document, dict) or (
        document.get("version") != TAXONOMY_VERSION
    ):
        raise TaxonomyError("taxonomy confirmation must be a version 1 object")

    raw_account = document.get("account", "")
    if not isinstance(raw_account, str) or not raw_account.strip():
        raise TaxonomyError(
            "taxonomy confirmation must name the account it was reviewed for"
        )
    if raw_account.strip().lower() != (actual_account or "").strip().lower():
        raise TaxonomyError(
            "taxonomy confirmation account does not match the authenticated "
            "Gmail account"
        )

    entries = document.get("confirmed_categories")
    if not isinstance(entries, dict) or not entries:
        raise TaxonomyError(
            "taxonomy confirmation must contain a non-empty "
            "confirmed_categories object"
        )

    confirmed = {}
    for slug, digest in entries.items():
        if not isinstance(slug, str) or not SLUG_PATTERN.match(slug):
            raise TaxonomyError(
                f"taxonomy confirmation key {slug!r} is not a valid slug"
            )
        if not isinstance(digest, str) or not TAXONOMY_DIGEST_PATTERN.match(digest):
            raise TaxonomyError(
                f"taxonomy confirmation for {slug!r} must be a "
                "'sha256:<64 hex>' digest"
            )
        confirmed[slug] = digest.lower()
    return TaxonomyConfirmation(account=raw_account, confirmed=confirmed)


def render_review_sheet(taxonomy):
    """Plain text the owner reads before confirming: names and examples."""
    lines = [
        "Proposed categories for review",
        "=" * 30,
        "",
        "Labeling has already been applied using these categories.",
        "Drafting stays blocked for every category until you confirm it.",
        "",
    ]
    for index, entry in enumerate(taxonomy, start=1):
        lines.append(f"{index}. {entry['display']}   [{entry['slug']}]")
        if entry["description"]:
            lines.append(f"     {entry['description']}")
        for example in entry["examples"]:
            lines.append(f"     e.g.  {example}")
        lines.append(f"     digest {entry['digest'][:22]}...")
        lines.append("")
    return "\n".join(lines)
