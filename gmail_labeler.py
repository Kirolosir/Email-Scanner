"""Label application for the triage classifier, kept deliberately separate
from draft creation so the two can be tested and run independently.

Policy (from the coach's rules, not inferred):

  * Grad year - applied ONLY when the message/thread carries no year label
    already AND the classifier actually extracted a year from content. An
    existing year label is never overwritten.
  * Category  - matched against the account's real label list. No label is
    ever created. If nothing matches the category, that is logged and
    skipped.
  * Conflict  - if the message already carries a category label that
    disagrees with the classifier, nothing is applied; the disagreement is
    logged for manual review.
  * "unknown" category - never labeled, always logged.

Nothing here removes a label. apply_labels() sends addLabelIds only and
never removeLabelIds, so "never overwrite" holds at the API call itself,
not just in the policy above it.

Real names are supplied by triage.py's optional JSON label configuration.
The fallback names below are inert unless exact labels already exist in the
account; every resolved name is filtered against Gmail's existing label list.
"""
import logging
from dataclasses import dataclass, field

import account_profile as _PROFILE_MOD
from account_profile import load_profile as _load_profile

_PROFILE = _load_profile()

logger = logging.getLogger(__name__)

# Gmail API quota costs, in units.
UNITS_LABELS_LIST = 1
UNITS_MESSAGES_MODIFY = 5

# Values the classifier uses to mean "I could not determine this".
UNDETERMINED = {"", _PROFILE_MOD.UNKNOWN, "none", "n/a"}

# Categories eligible for an evidence-gated year label. Sourced from the
# account profile; previously duplicated here and in triage.py.
RECRUIT_YEAR_CATEGORIES = set(_PROFILE.evidence_categories)


@dataclass
class LabelDecision:
    """What labeling should happen for one message, and why.

    `add` holds label NAMES (resolved to ids at apply time). `skips` and
    `conflicts` are human-readable lines for the run log - conflicts are
    kept separate because they mean a human should look, whereas skips are
    routine.
    """
    add: list = field(default_factory=list)
    skips: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)

    @property
    def has_work(self):
        return bool(self.add)


def fetch_account_labels(service, throttle=None):
    """Return {label_name: label_id} for every label already in the account.

    This is the authoritative list; nothing in this module invents a label
    that is not in here.
    """
    if throttle is not None:
        throttle.consume(UNITS_LABELS_LIST)
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    return {label["name"]: label["id"] for label in labels}


# ---------------------------------------------------------------------
# FALLBACK EXAMPLE LABEL NAMES - prefer --label-config with real names.
#
# These are stand-ins so the pipeline is runnable end to end before the
# real label list is available. They are NOT guesses about what the
# coach's labels are called; nothing is ever created from them. A name
# here only has an effect if a label by exactly that name already exists
# in the account (see build_label_index), so a wrong placeholder is inert
# rather than harmful.
#
# Do not edit these for deployment; pass a reviewed JSON configuration.
# ---------------------------------------------------------------------
PLACEHOLDER_YEAR_LABELS = dict(_PROFILE.year_labels)

PLACEHOLDER_CATEGORY_LABELS = dict(_PROFILE.category_labels)


def build_label_index(account_labels,
                      year_labels=None,
                      category_labels=None):
    """Split the account's real labels into year labels and category labels.

    Returns (year_labels, category_labels), e.g.
        year_labels     = {"2027": "<real label name>", ...}
        category_labels = {"recruit_intro": "<real label name>", ...}

    Both are filtered against `account_labels`, so every value returned is
    guaranteed to be a label that already exists. A year or category whose
    label is absent simply does not appear in the result, and
    decide_labels() then records it as a skip - which is the "don't guess,
    don't create" behavior we want.

    Defaults to the PLACEHOLDER_* maps above. Pass explicit maps to use
    the account's real names without editing this module.
    """
    year_source = PLACEHOLDER_YEAR_LABELS if year_labels is None else year_labels
    category_source = (
        PLACEHOLDER_CATEGORY_LABELS if category_labels is None else category_labels
    )

    present_years = {
        year: name for year, name in year_source.items()
        if name in account_labels
    }
    present_categories = {
        category: name for category, name in category_source.items()
        if name in account_labels
    }

    missing = sorted(
        set(year_source.values()) | set(category_source.values())
    ) if not (present_years or present_categories) else []
    if missing:
        logger.warning(
            "No configured label names exist in this account; nothing will be "
            "labeled. Configured names: %s", ", ".join(missing)
        )

    return present_years, present_categories


def _is_undetermined(value):
    return (value or "").strip().lower() in UNDETERMINED


def decide_labels(classification, current_label_names,
                  year_labels, category_labels):
    """Decide which labels to add to one message. Pure - makes no API calls.

    Args:
        classification: dict from gemini_client.classify(), with
            "category" and "grad_year" keys.
        current_label_names: label names already on the message (or on its
            thread - the caller chooses the scope; the policy is the same
            either way).
        year_labels: {year: real_label_name} for years that exist as labels.
        category_labels: {category: real_label_name} for categories that
            exist as labels.

    Returns a LabelDecision. Never returns a label that is not a value in
    year_labels/category_labels, so it cannot name a label that does not
    exist.
    """
    decision = LabelDecision()
    current = set(current_label_names or ())

    category = (classification.get("category") or "").strip().lower()
    grad_year = (classification.get("grad_year") or "").strip()
    sender_type = (classification.get("sender_type") or "").strip().lower()
    confidence = (classification.get("confidence") or "").strip().lower()
    local_grad_year = (
        classification.get("local_grad_year") or ""
    ).strip()

    # --- category ---
    if _is_undetermined(category):
        decision.skips.append("category is unknown; not labeling")
    else:
        target = category_labels.get(category)
        # Category labels already on this message, whatever they are.
        present = sorted(name for name in category_labels.values()
                         if name in current)

        if target is None:
            decision.skips.append(
                f"no existing label matches category {category!r}; not creating one"
            )
        elif target in current:
            decision.skips.append(
                f"category label {target!r} already present; nothing to do"
            )
        elif present:
            decision.conflicts.append(
                f"classifier says {category!r} -> {target!r}, but message "
                f"already has {', '.join(repr(p) for p in present)}; "
                "left unchanged for manual review"
            )
        else:
            decision.add.append(target)

    # --- grad year ---
    present_years = sorted(name for name in year_labels.values()
                           if name in current)
    if present_years:
        decision.skips.append(
            f"year label {present_years[0]!r} already on message; not overwritten"
        )
    elif _is_undetermined(grad_year):
        decision.skips.append("classifier extracted no grad year; not labeling")
    elif not classification.get(
        "year_label_eligible",
        sender_type == "recruit" and category in RECRUIT_YEAR_CATEGORIES,
    ):
        decision.skips.append(
            f"year {grad_year!r} not applied because sender/category is not "
            "a verified recruit message"
        )
    elif confidence != "high":
        decision.skips.append(
            f"year {grad_year!r} not applied because confidence is not high"
        )
    elif local_grad_year != grad_year:
        decision.skips.append(
            f"year {grad_year!r} not applied without matching deterministic "
            "current-message evidence"
        )
    else:
        target = year_labels.get(grad_year)
        if target is None:
            decision.skips.append(
                f"no existing label matches grad year {grad_year!r}; "
                "not creating one"
            )
        else:
            decision.add.append(target)

    return decision


def apply_labels(service, message_id, label_names, account_labels,
                 throttle=None):
    """Add the named labels to a message. Returns the label ids applied.

    Sends addLabelIds only - never removeLabelIds - so this can add a
    label but can never strip or replace one.

    Raises KeyError if asked for a label that is not in account_labels;
    that would mean a caller bypassed decide_labels(), and creating the
    label implicitly is exactly what we must not do.
    """
    if not label_names:
        return []

    label_ids = [account_labels[name] for name in label_names]

    if throttle is not None:
        throttle.consume(UNITS_MESSAGES_MODIFY)
    service.users().messages().modify(
        userId="me", id=message_id, body={"addLabelIds": label_ids}
    ).execute()
    return label_ids


def log_decision(message_id, decision):
    """Emit a decision's skips and conflicts to the run log.

    Conflicts go out at WARNING because they are the ones a human needs to
    look at; routine skips are INFO.
    """
    for conflict in decision.conflicts:
        logger.warning("[%s] label conflict: %s", message_id, conflict)
    for skip in decision.skips:
        logger.info("[%s] label skipped: %s", message_id, skip)
