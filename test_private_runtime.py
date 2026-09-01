"""Offline tests for process locking and PII-free private status."""
import json
import os

import pytest

from private_runtime import (
    AlreadyRunningError,
    ExclusiveRunLock,
    RunStatus,
)


def mode(path):
    return os.stat(path).st_mode & 0o777


def test_same_target_lock_conflicts_and_releases(tmp_path):
    first = ExclusiveRunLock(tmp_path / "locks", "same-target")
    second = ExclusiveRunLock(tmp_path / "locks", "same-target")
    first.acquire()
    try:
        with pytest.raises(AlreadyRunningError):
            second.acquire()
    finally:
        first.release()
    with second:
        assert second.path.name.startswith("run-")
        assert "same-target" not in second.path.name
    assert mode(tmp_path / "locks") == 0o700
    assert mode(second.path) == 0o600


def test_lock_releases_after_exception_and_separate_targets_do_not_conflict(tmp_path):
    lock_dir = tmp_path / "locks"
    with pytest.raises(RuntimeError):
        with ExclusiveRunLock(lock_dir, "target-a"):
            with ExclusiveRunLock(lock_dir, "target-b"):
                raise RuntimeError("offline fixture")
    with ExclusiveRunLock(lock_dir, "target-a"):
        pass


def test_status_is_atomic_private_and_contains_no_pii(tmp_path):
    path = tmp_path / "private" / "status.json"
    status = RunStatus(path)
    status.start("daily:scheduled")
    status.finish(
        True,
        {"scanned": 3, "drafted": 1, "needs_review": 2},
        ["safe_error_code"],
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["last_run"]["counts"]["scanned"] == 3
    assert document["last_successful_at"]
    text = path.read_text(encoding="utf-8")
    assert "student@example.test" not in text
    assert "PRIVATE SUBJECT" not in text
    assert mode(path.parent) == 0o700
    assert mode(path) == 0o600
    assert not list(path.parent.glob(f".{path.name}.*"))
