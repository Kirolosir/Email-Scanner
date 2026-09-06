"""Offline tests for connection leasing and timezone-correct scheduling.

Every decision takes an injected clock, so none of this waits on real time.
"""
import ast
import datetime as dt
import json
from pathlib import Path

import pytest

import connection_schedule
from connection_schedule import (
    DEFAULT_GRACE_MINUTES,
    FileLeaseBackend,
    LeaseError,
    LeaseLost,
    ConnectionLease,
    is_due,
    next_run,
    require_distributed,
    scheduled_datetime,
)
import connection as conn


UTC = dt.timezone.utc


def _seat(tmp_path, tz="America/New_York", run_at="18:00", enabled=True,
          account="coach@example.test", root=None):
    """One connection, established directly rather than through a roster."""
    root = root or tmp_path
    connection = conn.connect(root, account, timezone=tz, run_at=run_at)
    connection.enabled = enabled
    return connection


def _backend(tmp_path):
    return FileLeaseBackend(tmp_path / "leases")


# ---------------------------------------------------------------------
# Leasing
# ---------------------------------------------------------------------

def test_a_second_holder_is_refused_while_the_lease_is_live(tmp_path):
    backend = _backend(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    first = ConnectionLease(backend, "coach", owner="instance-a")
    second = ConnectionLease(backend, "coach", owner="instance-b")

    assert first.acquire(now) is True
    assert second.acquire(now) is False, (
        "two instances both acquired the same seat's lease"
    )


def test_an_expired_lease_is_reclaimable_without_a_human(tmp_path):
    backend = _backend(tmp_path)
    start = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    stalled = ConnectionLease(backend, "coach", owner="crashed", ttl_seconds=600)
    assert stalled.acquire(start) is True

    later = start + dt.timedelta(seconds=601)
    successor = ConnectionLease(backend, "coach", owner="fresh")
    assert successor.acquire(later) is True


def test_a_superseded_holder_discovers_it_lost_the_lease(tmp_path):
    """The fence is what a stalled holder checks; its own clock cannot help."""
    backend = _backend(tmp_path)
    start = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    stalled = ConnectionLease(backend, "coach", owner="stalled", ttl_seconds=600)
    stalled.acquire(start)

    later = start + dt.timedelta(seconds=601)
    ConnectionLease(backend, "coach", owner="successor").acquire(later)

    assert stalled.held(later) is False
    with pytest.raises(LeaseLost):
        stalled.renew(later)


def test_the_fence_alone_catches_a_same_owner_reacquisition(tmp_path):
    """Isolates the fence from the owner check.

    A restarted instance can legitimately reuse its own owner identity. When
    it does, the previous holder's owner check passes and only the fence can
    tell it that it was superseded - so the fence needs a test where the owner
    matches, or a mutation removing it goes unnoticed.
    """
    backend = _backend(tmp_path)
    start = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    first = ConnectionLease(backend, "coach", owner="instance-a", ttl_seconds=600)
    assert first.acquire(start) is True

    later = start + dt.timedelta(seconds=601)
    restarted = ConnectionLease(backend, "coach", owner="instance-a", ttl_seconds=600)
    assert restarted.acquire(later) is True
    assert restarted.fence == first.fence + 1

    # Same owner string, higher fence: only the fence can reveal this.
    assert first.held(later) is False
    with pytest.raises(LeaseLost):
        first.renew(later)


def test_the_fence_increases_on_every_acquisition(tmp_path):
    backend = _backend(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    fences = []
    for index in range(3):
        lease = ConnectionLease(backend, "coach", owner=f"o{index}", ttl_seconds=1)
        assert lease.acquire(now + dt.timedelta(seconds=index * 5)) is True
        fences.append(lease.fence)
    assert fences == sorted(set(fences)) == [1, 2, 3]


def test_renewal_extends_the_lease(tmp_path):
    backend = _backend(tmp_path)
    start = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    lease = ConnectionLease(backend, "coach", owner="a", ttl_seconds=600)
    lease.acquire(start)
    lease.renew(start + dt.timedelta(seconds=500))
    assert lease.held(start + dt.timedelta(seconds=900)) is True


def test_release_frees_the_seat_for_another_holder(tmp_path):
    backend = _backend(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    first = ConnectionLease(backend, "coach", owner="a")
    first.acquire(now)
    assert first.release() is True
    assert ConnectionLease(backend, "coach", owner="b").acquire(now) is True


def test_release_by_a_non_holder_does_nothing(tmp_path):
    backend = _backend(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    ConnectionLease(backend, "coach", owner="a").acquire(now)
    assert ConnectionLease(backend, "coach", owner="b").release() is False


def test_seats_do_not_block_each_other(tmp_path):
    backend = _backend(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    assert ConnectionLease(backend, "coach", owner="a").acquire(now) is True
    assert ConnectionLease(backend, "operator", owner="a").acquire(now) is True


def test_context_manager_refuses_a_busy_seat(tmp_path):
    backend = _backend(tmp_path)
    ConnectionLease(backend, "coach", owner="a").acquire()
    with pytest.raises(LeaseError, match="already running"):
        with ConnectionLease(backend, "coach", owner="b"):
            pass


def test_a_local_backend_is_refused_for_multi_instance(tmp_path):
    """The guard that stops a local lease pretending to coordinate."""
    with pytest.raises(LeaseError, match="one host only"):
        require_distributed(_backend(tmp_path))


def test_a_distributed_backend_is_accepted(tmp_path):
    class Shared(FileLeaseBackend):
        distributed = True
    assert require_distributed(Shared(tmp_path)) is not None


# ---------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------

def test_the_run_instant_is_in_the_seats_own_timezone(tmp_path):
    seat = _seat(tmp_path, tz="America/Los_Angeles", run_at="18:00")
    target = scheduled_datetime(seat, dt.date(2026, 9, 6))
    assert (target.hour, target.minute) == (18, 0)
    # 6pm Pacific in September is 01:00 UTC the next day.
    assert target.astimezone(UTC).hour == 1


def test_two_seats_in_different_zones_are_due_at_different_instants(tmp_path):
    east = _seat(tmp_path / "e", tz="America/New_York", run_at="18:00")
    west = _seat(tmp_path / "w", tz="America/Los_Angeles", run_at="18:00")
    at_2201_utc = dt.datetime(2026, 9, 6, 22, 1, tzinfo=UTC)  # 18:01 EDT
    assert is_due(east, at_2201_utc)[0] is True
    assert is_due(west, at_2201_utc)[0] is False


def test_not_due_before_the_scheduled_time(tmp_path):
    seat = _seat(tmp_path)
    due, reason = is_due(seat, dt.datetime(2026, 9, 6, 21, 59, tzinfo=UTC))
    assert due is False and "before the scheduled" in reason


def test_not_due_twice_in_one_local_day(tmp_path):
    seat = _seat(tmp_path)
    now = dt.datetime(2026, 9, 6, 22, 5, tzinfo=UTC)
    due, reason = is_due(seat, now, last_completed_date=dt.date(2026, 9, 6))
    assert due is False and "already completed" in reason


def test_a_missed_window_runs_late_within_grace(tmp_path):
    seat = _seat(tmp_path)
    # 18:00 EDT is 22:00 UTC; an hour late is still inside the grace period.
    assert is_due(seat, dt.datetime(2026, 9, 6, 23, 0, tzinfo=UTC))[0] is True


def test_an_overnight_outage_does_not_fire_at_4am(tmp_path):
    """Only today's window is ever considered.

    An outage spanning yesterday's run means yesterday is skipped, not fired
    at whatever hour the scheduler happens to come back. The seat simply waits
    for its own next window.
    """
    seat = _seat(tmp_path)
    at_4am = dt.datetime(2026, 9, 7, 8, 0, tzinfo=UTC)  # 04:00 EDT, next day
    due, reason = is_due(seat, at_4am)
    assert due is False
    assert "before the scheduled" in reason
    # And the next run is today's window, not a catch-up of yesterday's.
    assert next_run(seat, at_4am).date() == dt.date(2026, 9, 7)


def test_grace_boundary_is_respected_exactly(tmp_path):
    """Same-day lateness runs; past the grace period it skips, and says so."""
    seat = _seat(tmp_path)
    target_utc = dt.datetime(2026, 9, 6, 22, 0, tzinfo=UTC)
    inside = target_utc + dt.timedelta(minutes=DEFAULT_GRACE_MINUTES)
    outside = target_utc + dt.timedelta(minutes=DEFAULT_GRACE_MINUTES + 1)
    assert is_due(seat, inside)[0] is True
    late_due, late_reason = is_due(seat, outside)
    assert late_due is False
    assert "missed the window" in late_reason


def test_a_disabled_seat_is_never_due(tmp_path):
    seat = _seat(tmp_path, enabled=False)
    due, reason = is_due(seat, dt.datetime(2026, 9, 6, 22, 5, tzinfo=UTC))
    assert due is False and "disabled" in reason


def test_next_run_rolls_to_tomorrow_once_today_has_passed(tmp_path):
    seat = _seat(tmp_path)
    before = next_run(seat, dt.datetime(2026, 9, 6, 12, 0, tzinfo=UTC))
    after = next_run(seat, dt.datetime(2026, 9, 6, 23, 0, tzinfo=UTC))
    assert before.date() == dt.date(2026, 9, 6)
    assert after.date() == dt.date(2026, 9, 7)


def test_scheduling_survives_a_dst_transition(tmp_path):
    """US DST ends 2026-11-01. 18:00 local must stay 18:00 local."""
    seat = _seat(tmp_path)
    before = scheduled_datetime(seat, dt.date(2026, 10, 31))
    after = scheduled_datetime(seat, dt.date(2026, 11, 2))
    assert before.hour == after.hour == 18
    # The same wall clock maps to different UTC offsets across the change.
    assert before.utcoffset() != after.utcoffset()




# ---------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------

def test_scheduling_never_reads_the_wall_clock_in_a_decision():
    """Every decision takes `now`, so behaviour is testable without waiting."""
    tree = ast.parse(Path("connection_schedule.py").read_text(encoding="utf-8"))
    for name in ("is_due", "next_run", "scheduled_datetime"):
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        calls = {
            ast.unparse(node.func) for node in ast.walk(function)
            if isinstance(node, ast.Call)
        }
        assert not {"dt.datetime.now", "datetime.now", "time.time"} & calls, (
            f"{name} reads the clock instead of taking it as an argument"
        )


def test_the_module_never_runs_a_job_or_touches_the_network():
    tree = ast.parse(Path("connection_schedule.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("subprocess", "socket", "urllib", "requests",
                      "gmail_auth", "gemini_client", "daily_triage", "triage"):
        assert forbidden not in imported, f"connection_schedule imports {forbidden}"
