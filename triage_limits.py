"""Shared, side-effect-free limits for triage planning."""
from __future__ import annotations


SCHEDULED_LIMIT_FLAGS = {
    "max_scan": "--max-scan",
    "limit": "--limit",
    "max_drafts": "--max-drafts",
}


def validate_max_drafts(value):
    """Accept ``None`` or a nonnegative integer draft limit."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("--max-drafts must be zero or greater")
    return value


def validate_scheduled_limits(scheduled, *, max_scan, limit, max_drafts):
    """Require explicit, bounded limits before an unattended run starts."""
    if not scheduled:
        return
    values = {
        "max_scan": max_scan,
        "limit": limit,
        "max_drafts": max_drafts,
    }
    missing = [
        flag for name, flag in SCHEDULED_LIMIT_FLAGS.items()
        if values[name] is None
    ]
    if missing:
        raise ValueError(
            "--scheduled requires explicit limits: " + ", ".join(missing)
        )


def requires_new_draft(plan):
    """Whether executing ``plan`` would create a new Gmail draft."""
    return bool(
        plan.get("template") is not None
        and not plan.get("draft_already_owned", False)
    )


def plans_within_draft_limit(plans, max_drafts):
    """Admit plans without exceeding the new-draft budget.

    A draft-bearing plan that does not fit is deferred in full. Non-drafting
    plans can still be processed after the draft budget is exhausted.
    """
    validate_max_drafts(max_drafts)
    if max_drafts is None:
        return list(plans), []

    admitted = []
    deferred = []
    planned_drafts = 0
    for plan in plans:
        if requires_new_draft(plan):
            if planned_drafts >= max_drafts:
                deferred.append(plan)
                continue
            planned_drafts += 1
        admitted.append(plan)
    return admitted, deferred
