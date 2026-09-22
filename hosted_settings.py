"""Validated, fail-closed settings updates for the hosted dashboard.

Saving settings is the account owner's explicit approval of the displayed
label set and unsent-draft policy. The connection is disabled before any of
the related files change and re-enabled only after the config, taxonomy
confirmation, drafting approval, and pending Gmail-label setup record all exist.
A crash or partial disk failure therefore stops scheduled work instead of
running with a half-old approval bundle.
"""
from __future__ import annotations

import hashlib
import json
import datetime as dt
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import account_profile
import approve_account
import connection
from private_runtime import atomic_write_json
from taxonomy import sanitize_slug, validate_label_name


MAX_CATEGORIES = 12
# The ceiling the dashboard will accept for one run's scan size. It exists so
# a typo cannot request an unbounded run, not to ration mail: a day's inbox
# should fit inside one run rather than leaving a remainder for tomorrow.
# Backlog larger than this is cleared by the resumable history scan.
MAX_MESSAGES_PER_RUN = 2000
MAX_WRITES_PER_MESSAGE = 5
PENDING_LABEL_SETUP = "label-setup-pending.json"
LABEL_SETUP_POLICY = "label-setup-policy.json"
GMAIL_LABEL_CATALOG = "gmail-label-catalog.json"
CREATE_MISSING_LABELS = "create_missing"
EXISTING_LABELS_ONLY = "existing_only"
LABEL_SETUP_MODES = {CREATE_MISSING_LABELS, EXISTING_LABELS_ONLY}
MAX_DRAFT_GUIDANCE_CHARS = 1200
DEFAULT_DRAFT_GUIDANCE = (
    "Sound like a real person, not a customer-service template. Respond to the "
    "sender's actual point, mention one useful detail from their message when "
    "appropriate, and end with a clear next step if one is needed. Keep the "
    "tone warm, direct, and natural."
)
DEFAULT_SYSTEM_LABELS = {
    "needs_review": "Needs Review",
    "processed": "Processed",
}


class SettingsError(ValueError):
    pass


def _bounded_int(value, name, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SettingsError(f"{name} must be a number") from exc
    if isinstance(value, bool) or not minimum <= parsed <= maximum:
        raise SettingsError(f"{name} must be from {minimum} to {maximum}")
    return parsed


def parse_label_lines(raw, system_labels=None):
    """Parse ``Display | Gmail/Label`` lines into reviewed categories."""
    lines = [line.strip() for line in str(raw or "").splitlines()
             if line.strip()]
    if not lines:
        raise SettingsError("add at least one label")
    if len(lines) > MAX_CATEGORIES:
        raise SettingsError(f"use at most {MAX_CATEGORIES} labels")

    categories = []
    slugs = set()
    names = set()
    for line in lines:
        display, separator, label = line.partition("|")
        display = display.strip()
        label = label.strip() if separator else display
        if not display:
            raise SettingsError("every label needs a display name")
        try:
            slug = sanitize_slug(display)
            validate_label_name(label)
        except ValueError as exc:
            raise SettingsError(str(exc)) from exc
        folded = label.casefold()
        if slug in slugs:
            raise SettingsError(f"duplicate category {display!r}")
        if folded in names:
            raise SettingsError(f"duplicate Gmail label {label!r}")
        slugs.add(slug)
        names.add(folded)
        categories.append({
            "slug": slug,
            "display": display[:128],
            "description": f"Messages best categorized as {display[:128]}.",
            "examples": [],
            "label": label,
            "drafting": {"mode": "generic"},
        })

    if "other" not in slugs:
        if len(categories) >= MAX_CATEGORIES:
            raise SettingsError(
                "include an Other category within the 12-label limit"
            )
        categories.append({
            "slug": "other",
            "display": "Other",
            "description": "Replyable messages that fit no narrower category.",
            "examples": [],
            "label": "Other",
            "drafting": {"mode": "generic"},
        })
        names.add("other")

    system_labels = system_labels or DEFAULT_SYSTEM_LABELS
    for system_name in system_labels.values():
        if system_name.casefold() in names:
            raise SettingsError(
                f"{system_name!r} is reserved for run tracking"
            )
    return categories


def label_setup_mode(form):
    mode = str(form.get("label_setup_mode", CREATE_MISSING_LABELS)).strip()
    if mode not in LABEL_SETUP_MODES:
        raise SettingsError("choose a valid Gmail label setup mode")
    return mode


def _system_labels(form):
    labels = {
        "needs_review": str(
            form.get("needs_review_label", DEFAULT_SYSTEM_LABELS["needs_review"])
        ).strip(),
        "processed": str(
            form.get("processed_label", DEFAULT_SYSTEM_LABELS["processed"])
        ).strip(),
    }
    try:
        for name in labels.values():
            validate_label_name(name)
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc
    if len({name.casefold() for name in labels.values()}) != len(labels):
        raise SettingsError("review and processed labels must be different")
    return labels


def save_gmail_label_catalog(active, account_labels, *, now=None):
    """Save only Gmail label names for authenticated settings suggestions."""
    names = account_labels.keys() if isinstance(account_labels, dict) \
        else account_labels
    labels = sorted({
        str(name) for name in names
        if isinstance(name, str) and name.strip() and len(name) <= 225
    }, key=str.casefold)
    refreshed = now or dt.datetime.now(dt.timezone.utc)
    atomic_write_json(Path(active) / GMAIL_LABEL_CATALOG, {
        "version": 1,
        "refreshed_at": refreshed.astimezone(dt.timezone.utc).isoformat(),
        "labels": labels,
    })


def load_gmail_label_catalog(active):
    path = Path(active) / GMAIL_LABEL_CATALOG
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError("the Gmail label list could not be read") from exc
    if (not isinstance(document, dict)
            or set(document) != {"version", "refreshed_at", "labels"}
            or document.get("version") != 1
            or not isinstance(document.get("refreshed_at"), str)
            or not isinstance(document.get("labels"), list)
            or not all(isinstance(name, str) and name.strip()
                       and len(name) <= 225 for name in document["labels"])):
        raise SettingsError("the Gmail label list needs to be refreshed")
    return tuple(document["labels"])


def load_label_setup_mode(active):
    try:
        with (Path(active) / LABEL_SETUP_POLICY).open(
                encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return CREATE_MISSING_LABELS
    except (OSError, json.JSONDecodeError):
        return CREATE_MISSING_LABELS
    mode = document.get("mode") if isinstance(document, dict) else None
    return mode if mode in LABEL_SETUP_MODES else CREATE_MISSING_LABELS


def build_settings_document(occupant, form):
    system_labels = _system_labels(form)
    categories = parse_label_lines(form.get("labels"), system_labels)
    timezone = str(form.get("timezone", "")).strip()
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SettingsError("choose a valid timezone") from exc
    run_at = str(form.get("run_at", "")).strip()
    if not connection.RUN_AT.fullmatch(run_at):
        raise SettingsError("daily run time must use HH:MM")
    display_name = str(form.get("display_name", "")).strip()
    role = str(form.get("role", "")).strip()
    organization = str(form.get("organization", "")).strip()
    signature = str(form.get("signature", "")).strip()
    raw_guidance = form.get("draft_guidance")
    draft_guidance = (
        DEFAULT_DRAFT_GUIDANCE
        if raw_guidance is None else str(raw_guidance).strip()
    )
    if not display_name or len(display_name) > 120:
        raise SettingsError("display name is required and must be under 120 characters")
    if len(role) > 120:
        raise SettingsError("coach role must be under 120 characters")
    if len(organization) > 160:
        raise SettingsError("school or program must be under 160 characters")
    if not signature or len(signature) > 500:
        raise SettingsError("signature is required and must be under 500 characters")
    if not draft_guidance or len(draft_guidance) > MAX_DRAFT_GUIDANCE_CHARS:
        raise SettingsError(
            "draft style is required and must be under 1200 characters"
        )
    if form.get("confirm_unsent_drafts") != "yes":
        raise SettingsError(
            "confirm that generated responses are unsent drafts requiring review"
        )

    document = {
        "version": 1,
        "account": occupant.account,
        "timezone": timezone,
        "taxonomy": categories,
        "system_labels": system_labels,
        "draft_all_replyable_messages": True,
        "fallback_category": "other",
        "ai_drafting": {
            "display_name": display_name,
            "role": role,
            "organization": organization,
            "signature": signature,
            "default_guidance": draft_guidance,
            "max_words": 160,
        },
    }
    # This performs the same strict schema and drafting-policy validation the
    # scheduled run will perform later, before any state file changes.
    try:
        profile = account_profile.load_profile_document(document)
    except ValueError as exc:
        raise SettingsError("settings could not be validated") from exc
    max_scan = _bounded_int(
        form.get("max_scan"), "scan limit", 1, MAX_MESSAGES_PER_RUN
    )
    # The owner chooses one comprehensible batch size. These internal limits
    # are derived so every candidate can receive its category, evidence and
    # review labels, the Processed label, and one unsent draft.
    limits = {
        "max_scan": max_scan,
        "limit": max_scan * MAX_WRITES_PER_MESSAGE,
        "max_drafts": max_scan,
    }
    return document, profile, run_at, limits


def document_digest(document):
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def save_settings(root, form):
    """Validate and commit a complete settings/approval bundle."""
    root = Path(root)
    with connection.lifecycle_lock(root):
        occupant = connection.current(root)
        if occupant is None:
            raise SettingsError("connect Gmail before saving settings")
        document, profile, run_at, limits = build_settings_document(
            occupant, form
        )
        mode = label_setup_mode(form)
        try:
            taxonomy_document, ai_document = approve_account.build_documents(
                profile
            )
        except ValueError as exc:
            raise SettingsError("settings approval could not be created") from exc
        if ai_document is None:
            raise SettingsError("drafting approval was not produced")

        active = Path(occupant.directory)
        configured_labels = sorted(
            [entry["label"] for entry in document["taxonomy"]]
            + list(document["system_labels"].values())
        )
        if mode == EXISTING_LABELS_ONLY:
            catalog = load_gmail_label_catalog(active)
            if catalog is None:
                raise SettingsError(
                    "reconnect Gmail once to load its current labels before "
                    "choosing existing labels only; nothing was changed"
                )
            present = set(catalog)
            missing = [name for name in configured_labels if name not in present]
            if missing:
                shown = ", ".join(missing[:5])
                suffix = "…" if len(missing) > 5 else ""
                raise SettingsError(
                    f"these exact Gmail labels do not exist: {shown}{suffix}; "
                    "nothing was created"
                )
        # Stop the timer before the multi-file bundle changes. Re-enabling is
        # the commit marker; any failure in between remains visibly disabled.
        connection.update_settings(root, occupant.account, enabled=False)
        try:
            atomic_write_json(active / "account.json", document)
            atomic_write_json(
                active / "taxonomy-confirmation.json", taxonomy_document
            )
            atomic_write_json(active / "ai-drafting-approval.json", ai_document)
            atomic_write_json(active / LABEL_SETUP_POLICY, {
                "version": 1,
                "mode": mode,
            })
            atomic_write_json(active / PENDING_LABEL_SETUP, {
                "version": 1,
                "account_config_digest": document_digest(document),
                "labels": configured_labels,
                "mode": mode,
            })
        except OSError as exc:
            raise SettingsError(
                f"settings could not be saved ({type(exc).__name__}); "
                "daily runs remain paused"
            ) from exc

        return connection.update_settings(
            root, occupant.account,
            timezone=profile.timezone, run_at=run_at, enabled=True,
            limits=limits,
        )
