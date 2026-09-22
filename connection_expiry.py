"""When the connection is expected to lapse, and how sure we are.

Testing-mode refresh tokens expire in about seven days. Google states the rule
directly: a project with an OAuth consent screen configured for an external
user type and a publishing status of "Testing" is issued a refresh token
expiring in 7 days, unless the only scopes requested are a subset of name,
email address and profile. This deployment requests gmail.modify, and Internal
is unavailable on a personal-Gmail-based project, so the lapse is a permanent
characteristic of the design rather than a defect to route around.

The failure this module exists to prevent is a scheduled run quietly stopping
and nobody noticing for days. So the state is computed and shown BEFORE it
bites, not discovered afterwards.

A COUNTDOWN IS A PREDICTION, NOT AN OBSERVATION. Nothing here has verified
anything with Google. The number is a documented policy applied to a stored
issue time, and a token can also be revoked earlier by the user or an
administrator. Two consequences, both deliberate:

  * every result carries basis="prediction" and the last successful run
    alongside, so an interface cannot present the estimate on its own; and
  * evidence outranks the estimate. A run that succeeded AFTER the predicted
    expiry proves the prediction wrong, and the state says so instead of
    insisting the connection is dead while it demonstrably works.

That second rule is also what stops a wrong prediction becoming a trap: if the
estimate were allowed to block attempts unconditionally, a token that outlives
seven days could never prove it.
"""
from __future__ import annotations

import datetime as dt


# Google's documented lifetime for a Testing-status external-user-type project.
TESTING_MODE_TOKEN_LIFETIME_DAYS = 7

# How long before the expected lapse the interface should start insisting.
# Two days leaves a weekend to act in.
EXPIRING_SOON_DAYS = 2

HEALTHY = "healthy"
EXPIRING = "expiring"
EXPIRED = "expired"
UNKNOWN = "unknown"

# The state is always a prediction. There is no code path that sets this to
# anything else, because nothing in this module observes a token's validity.
BASIS = "prediction"


def _parse(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        stamp = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.timezone.utc)


def expected_expiry(connection):
    """When the current token is expected to lapse, or None if unknowable.

    last_authorized_at is exactly the moment the current token was issued -
    connect() sets it on the initial connection and moves it on every
    re-authorisation - so it needs no separate field that could drift from it.
    """
    issued = _parse(getattr(connection, "last_authorized_at", ""))
    if issued is None:
        return None
    return issued + dt.timedelta(days=TESTING_MODE_TOKEN_LIFETIME_DAYS)


def _describe(days):
    if days < 0:
        return "Connection expired — reconnect required"
    if days < 1:
        return "Connection expected to expire in under a day"
    whole = int(days)
    unit = "day" if whole == 1 else "days"
    return f"Connection expected to last {whole} more {unit}"


def expiry_state(connection, now, last_successful_run=None):
    """The connection's expected expiry, with the evidence beside it.

    Returns a mapping an interface can render directly. `state` is one of
    healthy, expiring, expired or unknown; `basis` is always "prediction".
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    expiry = expected_expiry(connection)
    evidence = _parse(last_successful_run)
    evidence_iso = evidence.isoformat(timespec="seconds") if evidence else None

    if expiry is None:
        return {
            "state": UNKNOWN,
            "expected_expiry": None,
            "days_remaining": None,
            "basis": BASIS,
            "last_successful_run": evidence_iso,
            "evidence_overrides_prediction": False,
            "summary": "Connection age unknown — reconnect to establish it",
        }

    days = (expiry - now).total_seconds() / 86400.0

    # Evidence outranks the estimate. A run that succeeded after the predicted
    # lapse proves the prediction wrong; saying "expired" over the top of that
    # would be asserting something already disproved.
    overridden = bool(evidence is not None and evidence > expiry)
    if overridden:
        state = HEALTHY
        summary = (
            "Past the expected window, but a run succeeded afterward — "
            "the estimate was wrong, not the connection"
        )
    elif days < 0:
        state, summary = EXPIRED, _describe(days)
    elif days <= EXPIRING_SOON_DAYS:
        state, summary = EXPIRING, _describe(days)
    else:
        state, summary = HEALTHY, _describe(days)

    return {
        "state": state,
        "expected_expiry": expiry.isoformat(timespec="seconds"),
        "days_remaining": round(days, 2),
        "basis": BASIS,
        "last_successful_run": evidence_iso,
        "evidence_overrides_prediction": overridden,
        "summary": summary,
    }


def should_attempt(connection, now, last_successful_run=None):
    """Whether a scheduled run is worth starting.

    False only when the connection is predicted expired AND nothing has
    succeeded since, so there is no reason to expect a working grant. Because
    a later successful run flips the state back to healthy, a token that
    outlives the documented window is never permanently locked out by its own
    estimate - and a reconnection resets the clock regardless.
    """
    state = expiry_state(connection, now, last_successful_run)
    return state["state"] != EXPIRED, state
