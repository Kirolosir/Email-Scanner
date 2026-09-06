"""Fixed-roster seat registry for a small hosted deployment.

THREE SEATS, DECLARED, NOT DISCOVERED. There is no signup, no seat creation
at runtime, and no growth path. The roster is a reviewed file, and a seat that
is not in it does not exist. That is the whole tenancy model: at this size the
correct answer to multi-tenancy is to not have any, and to make the absence
enforceable rather than incidental.

Each seat owns a directory. Every per-seat artifact the single-operator system
already writes - the run journal, the PII-free status document, review reports,
draft logs - keeps its existing shape and its existing 0600/0700 discipline,
one directory down. Nothing about their privacy properties changes; only their
location does.

WHAT THIS MODULE DOES NOT DO. It never contacts Google, never decrypts a token
(see seat_tokens.py), and never runs a triage job. It resolves configuration
and nothing else, so it stays importable in a web process that must not be able
to do any of those things.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


# A hard ceiling, not a default. Raising it is a deliberate edit to a reviewed
# constant, which is the point: the roster cannot grow by accident, and a
# config that tries is rejected rather than truncated.
MAX_SEATS = 3

SEAT_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
EMAIL_SHAPED = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# 24-hour local wall clock, the shape the launchd example already uses.
RUN_AT = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

ALLOWED_SEAT_KEYS = frozenset({
    "id", "account", "timezone", "run_at", "directory",
    "account_config", "taxonomy_confirmation", "ai_drafting_approval",
    "max_scan", "limit", "max_drafts", "enabled", "_comment",
})

REQUIRED_SEAT_KEYS = frozenset({
    "id", "account", "timezone", "run_at", "directory", "account_config",
})


class SeatConfigError(ValueError):
    """A roster that cannot be trusted is not partially loaded."""


def _require(condition, message):
    if not condition:
        raise SeatConfigError(message)


class Seat:
    """One resolved seat. Paths are derived here and never from a request."""

    def __init__(self, document, root):
        self.id = document["id"]
        self.account = document["account"]
        self.timezone_name = document["timezone"]
        self.timezone = ZoneInfo(self.timezone_name)
        self.run_at = document["run_at"]
        self.enabled = bool(document.get("enabled", True))

        self.directory = (root / document["directory"]).resolve()
        self.account_config = (root / document["account_config"]).resolve()
        self.taxonomy_confirmation = self._optional(
            root, document.get("taxonomy_confirmation")
        )
        self.ai_drafting_approval = self._optional(
            root, document.get("ai_drafting_approval")
        )

        # Unattended runs must be bounded, exactly as validate_scheduled_limits
        # already requires of --scheduled on the command line.
        self.max_scan = int(document.get("max_scan", 25))
        self.limit = int(document.get("limit", 25))
        self.max_drafts = int(document.get("max_drafts", 5))

    @staticmethod
    def _optional(root, value):
        return (root / value).resolve() if value else None

    @property
    def hour(self):
        return int(self.run_at.split(":")[0])

    @property
    def minute(self):
        return int(self.run_at.split(":")[1])

    @property
    def state_path(self):
        return self.directory / "daily-state.json"

    @property
    def status_path(self):
        return self.directory / "daily-status.json"

    @property
    def review_dir(self):
        return self.directory / "review"

    @property
    def lock_dir(self):
        return self.directory / "locks"

    def __repr__(self):
        return f"<Seat {self.id} {self.run_at} {self.timezone_name}>"


def _validate_seat(document, seen_ids, seen_accounts):
    _require(isinstance(document, dict), "each seat must be an object")
    unexpected = sorted(set(document) - ALLOWED_SEAT_KEYS)
    _require(not unexpected, f"unsupported seat keys: {', '.join(unexpected)}")
    missing = sorted(REQUIRED_SEAT_KEYS - set(document))
    _require(not missing, f"seat is missing required keys: {', '.join(missing)}")

    seat_id = document["id"]
    _require(isinstance(seat_id, str) and SEAT_ID.match(seat_id),
             f"invalid seat id {seat_id!r}")
    _require(seat_id not in seen_ids, f"duplicate seat id {seat_id!r}")

    account = document["account"]
    _require(isinstance(account, str) and EMAIL_SHAPED.match(account),
             f"seat {seat_id!r} has an invalid account address")
    folded = account.strip().casefold()
    # Two seats pointing at one mailbox would run the same inbox twice on two
    # schedules, with two journals disagreeing about what was drafted.
    _require(folded not in seen_accounts,
             f"account {account!r} is configured for more than one seat")

    _require(isinstance(document["run_at"], str)
             and RUN_AT.match(document["run_at"]),
             f"seat {seat_id!r} run_at must be HH:MM in 24-hour local time")

    timezone_name = document["timezone"]
    _require(isinstance(timezone_name, str) and timezone_name.strip(),
             f"seat {seat_id!r} must name a timezone")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SeatConfigError(
            f"seat {seat_id!r} has an unknown timezone {timezone_name!r}"
        ) from exc

    for key in ("directory", "account_config"):
        value = document[key]
        _require(isinstance(value, str) and value.strip(),
                 f"seat {seat_id!r} needs a {key}")
        _require(not Path(value).is_absolute(),
                 f"seat {seat_id!r} {key} must be relative to the roster root")
        _require(".." not in Path(value).parts,
                 f"seat {seat_id!r} {key} must not escape the roster root")

    for key in ("taxonomy_confirmation", "ai_drafting_approval"):
        value = document.get(key)
        if value is not None:
            _require(isinstance(value, str) and value.strip(),
                     f"seat {seat_id!r} {key} must be a path or omitted")
            _require(not Path(value).is_absolute() and ".." not in Path(value).parts,
                     f"seat {seat_id!r} {key} must stay under the roster root")

    for key in ("max_scan", "limit", "max_drafts"):
        if key in document:
            value = document[key]
            _require(isinstance(value, int) and not isinstance(value, bool)
                     and value >= 0,
                     f"seat {seat_id!r} {key} must be a nonnegative integer")

    if "enabled" in document:
        _require(isinstance(document["enabled"], bool),
                 f"seat {seat_id!r} enabled must be true or false")

    seen_ids.add(seat_id)
    seen_accounts.add(folded)


def load_roster(path):
    """Load and fully validate the seat roster, or raise.

    Fails closed and fails whole: a roster with one bad seat loads no seats,
    because a partially valid roster is how a deployment ends up running two
    seats and silently skipping the third.
    """
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        raise SeatConfigError(f"roster is unreadable: {type(exc).__name__}") from exc
    except json.JSONDecodeError as exc:
        raise SeatConfigError("roster is not valid JSON") from exc

    _require(isinstance(document, dict), "roster must be a JSON object")
    unexpected = sorted(set(document) - {"version", "seats", "_comment"})
    _require(not unexpected, f"unsupported roster keys: {', '.join(unexpected)}")
    _require(document.get("version") == 1, "roster must be a version 1 object")

    seats = document.get("seats")
    _require(isinstance(seats, list) and seats, "roster must list at least one seat")
    _require(
        len(seats) <= MAX_SEATS,
        f"roster declares {len(seats)} seats; this deployment is capped at "
        f"{MAX_SEATS}. Raising the cap is a reviewed edit, not a config change.",
    )

    seen_ids, seen_accounts = set(), set()
    for entry in seats:
        _validate_seat(entry, seen_ids, seen_accounts)

    root = path.resolve().parent
    return [Seat(entry, root) for entry in seats]


def enabled_seats(roster):
    return [seat for seat in roster if seat.enabled]


def find_seat(roster, seat_id):
    """Look a seat up by id, or return None. Never used with request input."""
    for seat in roster:
        if seat.id == seat_id:
            return seat
    return None
