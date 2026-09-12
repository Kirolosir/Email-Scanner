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


def test_status_publishes_bounded_live_progress(tmp_path):
    path = tmp_path / "private" / "status.json"
    status = RunStatus(path)
    status.start("daily:scheduled")
    status.progress(
        "Creating Gmail labels and drafts", {"scanned": 50, "drafted": 7},
        current=8, total=50,
    )

    run = json.loads(path.read_text(encoding="utf-8"))["last_run"]
    assert run["outcome"] == "running"
    assert (run["current"], run["total"]) == (8, 50)
    assert run["stage"] == "Creating Gmail labels and drafts"
    assert run["counts"]["drafted"] == 7


# --------------------------------------------------------------------
# mkdir(parents=True, mode=0o700) applies the mode to the LAST component
# only; parents get the umask, 0755 in practice. A nested state_dir such
# as triage-state/<account> therefore produced a world-listable parent
# holding a private leaf, exposing which accounts are being triaged. This
# happened on the live pilot account, not just in theory.
# --------------------------------------------------------------------

def test_every_directory_created_on_the_way_is_private(tmp_path):
    import os
    import stat
    from private_runtime import ensure_private_directory

    leaf = tmp_path / "triage-state" / "someone" / "locks"
    ensure_private_directory(leaf)

    for path in (tmp_path / "triage-state",
                 tmp_path / "triage-state" / "someone",
                 leaf):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700, f"{path} is mode {mode:03o}, expected 700"


def test_a_pre_existing_ancestor_is_left_alone(tmp_path):
    """Permissions on a directory this call did not create are not ours to
    change; chmod on a shared parent we do not own raises EPERM."""
    import os
    import stat
    from private_runtime import ensure_private_directory

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)

    ensure_private_directory(shared / "private")

    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(shared / "private").st_mode) == 0o700
