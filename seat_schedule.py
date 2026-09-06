"""Timezone-correct, idempotent scheduling for a fixed seat roster.

WHY ExclusiveRunLock IS NOT ENOUGH HERE. That lock uses fcntl advisory file
locks, which coordinate processes on one host and nothing at all beyond it. It
is exactly right for a laptop and silently wrong on a platform that runs two
instances during a rolling deploy: both would acquire "the" lock on their own
filesystem and run the same seat's 6pm job concurrently, and part of what
currently prevents double-drafting IS that lock.

The replacement is a LEASE: a record, in storage both instances share, that
carries an owner, an expiry, and a monotonically increasing fence token. A
holder that stalls loses the lease by expiry rather than by being noticed, and
the fence lets a late waker detect that it was superseded instead of writing as
though it still held the lock.

The backend is injected. The filesystem backend here is correct for multiple
processes on ONE host and is what the tests exercise; a multi-instance
deployment must supply a shared-storage backend with the same semantics, and
`require_distributed` refuses to start rather than pretending a local lease
coordinates anything.

CLOCKS ARE INJECTED TOO. Scheduling logic that reads the wall clock directly is
scheduling logic that can only be tested by waiting, so every decision here
takes `now` as an argument.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
from pathlib import Path

from private_runtime import atomic_write_json, ensure_private_directory


# A lease outlives a normal run comfortably but not indefinitely: a crashed
# holder must become reclaimable without a human, and a live holder must renew
# rather than assume.
DEFAULT_LEASE_SECONDS = 30 * 60
RENEW_WITHIN_SECONDS = 5 * 60

# How late a missed window may still run. Past this the run is skipped rather
# than fired at the wrong time of day - a 6pm job starting at 4am is not a
# late 6pm job, it is a surprise.
DEFAULT_GRACE_MINUTES = 120


class LeaseError(RuntimeError):
    pass


class LeaseLost(LeaseError):
    """Raised when a holder discovers it was superseded."""


class FileLeaseBackend:
    """Shared-lease semantics over one filesystem.

    Correct for multiple processes on a single host. NOT correct across
    instances; see require_distributed.
    """

    distributed = False

    def __init__(self, directory):
        self.directory = Path(directory)

    def _path(self, key):
        return self.directory / f"lease-{key}.json"

    def read(self, key):
        try:
            with self._path(key).open(encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        return record if isinstance(record, dict) else None

    def write(self, key, record):
        ensure_private_directory(self.directory)
        atomic_write_json(self._path(key), record)

    def clear(self, key):
        try:
            os.unlink(self._path(key))
        except FileNotFoundError:
            pass


def require_distributed(backend):
    """Refuse to run multi-instance on a backend that cannot coordinate."""
    if not getattr(backend, "distributed", False):
        raise LeaseError(
            "this lease backend coordinates one host only; a multi-instance "
            "deployment must supply a shared-storage backend"
        )
    return backend


class SeatLease:
    """A fenced, expiring lease over one seat's scheduled work."""

    def __init__(self, backend, seat_id, owner=None,
                 ttl_seconds=DEFAULT_LEASE_SECONDS):
        self.backend = backend
        self.seat_id = seat_id
        self.owner = owner or f"{os.getpid()}-{secrets.token_hex(4)}"
        self.ttl = int(ttl_seconds)
        self.fence = None

    def _now(self, now):
        return now or dt.datetime.now(dt.timezone.utc)

    def acquire(self, now=None):
        """Take the lease if it is free or expired. Returns True on success.

        The fence increments on every successful acquisition, so a stalled
        previous holder can tell it has been superseded even if its own clock
        never noticed.
        """
        now = self._now(now)
        record = self.backend.read(self.seat_id)
        if record is not None:
            expires = _parse(record.get("expires_at"))
            if expires is not None and expires > now and record.get("owner") != self.owner:
                return False
        fence = int(record.get("fence", 0)) + 1 if record else 1
        self.backend.write(self.seat_id, {
            "owner": self.owner,
            "fence": fence,
            "acquired_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + dt.timedelta(seconds=self.ttl)).isoformat(
                timespec="seconds"),
        })
        self.fence = fence
        return True

    def renew(self, now=None):
        """Extend the lease. Raises LeaseLost if someone else took it."""
        now = self._now(now)
        record = self.backend.read(self.seat_id)
        if record is None or record.get("owner") != self.owner \
                or int(record.get("fence", -1)) != self.fence:
            raise LeaseLost(f"lease for {self.seat_id} was taken by another holder")
        self.backend.write(self.seat_id, {
            **record,
            "expires_at": (now + dt.timedelta(seconds=self.ttl)).isoformat(
                timespec="seconds"),
        })
        return True

    def held(self, now=None):
        """Whether this object still holds a live, un-superseded lease."""
        now = self._now(now)
        record = self.backend.read(self.seat_id)
        if record is None or record.get("owner") != self.owner:
            return False
        if int(record.get("fence", -1)) != self.fence:
            return False
        expires = _parse(record.get("expires_at"))
        return expires is not None and expires > now

    def release(self):
        record = self.backend.read(self.seat_id)
        if record and record.get("owner") == self.owner:
            self.backend.clear(self.seat_id)
            return True
        return False

    def __enter__(self):
        if not self.acquire():
            raise LeaseError(f"seat {self.seat_id} is already running")
        return self

    def __exit__(self, *_exc):
        self.release()
        return False


def _parse(value):
    if not isinstance(value, str):
        return None
    try:
        stamp = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.timezone.utc)


def scheduled_datetime(seat, local_date):
    """The seat's run instant on a given local date, in its own timezone."""
    return dt.datetime.combine(
        local_date, dt.time(hour=seat.hour, minute=seat.minute),
        tzinfo=seat.timezone,
    )


def is_due(seat, now, last_completed_date=None,
           grace_minutes=DEFAULT_GRACE_MINUTES):
    """Whether this seat should run at `now`, and why not if it should not.

    Returns (due, reason). Deliberately conservative in both directions: a
    seat that already ran today does not run again, and a window missed by
    more than the grace period is skipped rather than fired at a time the
    person did not choose.
    """
    if not seat.enabled:
        return False, "seat is disabled"

    local_now = now.astimezone(seat.timezone)
    today = local_now.date()

    if last_completed_date is not None and last_completed_date >= today:
        return False, "already completed today"

    target = scheduled_datetime(seat, today)
    if local_now < target:
        return False, "before the scheduled time"

    late_by = (local_now - target).total_seconds() / 60.0
    if late_by > grace_minutes:
        return False, (
            f"missed the window by {int(late_by)} minutes; skipping rather "
            "than running at an unexpected hour"
        )
    return True, "due"


def next_run(seat, now):
    """The next instant this seat is scheduled to run, in its timezone."""
    local_now = now.astimezone(seat.timezone)
    today_target = scheduled_datetime(seat, local_now.date())
    if local_now < today_target:
        return today_target
    return scheduled_datetime(
        seat, local_now.date() + dt.timedelta(days=1)
    )


def due_seats(roster, now, completed=None, grace_minutes=DEFAULT_GRACE_MINUTES):
    """Every seat due at `now`, in roster order.

    `completed` maps seat id to the last local date that seat finished, which
    is what the existing same-day guard already records per seat.
    """
    completed = completed or {}
    due = []
    for seat in roster:
        ready, _reason = is_due(
            seat, now, completed.get(seat.id), grace_minutes
        )
        if ready:
            due.append(seat)
    return due
