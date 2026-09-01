"""Private local runtime primitives for scheduled/offline-safe workflows."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import tempfile
from pathlib import Path

from message_safety import opaque_id


LOCKED_EXIT_CODE = 75


def ensure_private_directory(path):
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def atomic_write_json(path, document):
    """Atomically write JSON using directory 0700 and file 0600."""
    target = Path(path)
    ensure_private_directory(target.parent)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


class AlreadyRunningError(RuntimeError):
    pass


class ExclusiveRunLock:
    """Crash-safe, nonblocking advisory lock with an opaque filename."""

    def __init__(self, directory, target_key):
        self.directory = Path(directory)
        self.target_hash = opaque_id(target_key, length=24)
        self.path = self.directory / f"run-{self.target_hash}.lock"
        self._file = None

    def acquire(self):
        ensure_private_directory(self.directory)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        os.chmod(self.path, 0o600)
        lock_file = os.fdopen(descriptor, "a+", encoding="utf-8")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock_file.close()
            raise AlreadyRunningError("another run holds the target lock") from exc
        self._file = lock_file
        return self

    def release(self):
        if self._file is not None:
            try:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
                self._file = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *_exc_info):
        self.release()
        return False


class RunStatus:
    """PII-free atomic scheduler status document."""

    VERSION = 1
    COUNT_KEYS = {
        "scanned", "classified", "labeled", "drafted", "needs_review",
        "skipped", "failures",
    }

    def __init__(self, path):
        self.path = Path(path)
        self.data = {
            "version": self.VERSION,
            "last_attempted_at": None,
            "last_successful_at": None,
            "last_run": None,
        }
        if self.path.exists():
            try:
                candidate = json.loads(self.path.read_text(encoding="utf-8"))
                if (isinstance(candidate, dict)
                        and candidate.get("version") == self.VERSION):
                    self.data = candidate
            except (OSError, json.JSONDecodeError):
                # Status is observability-only; a corrupt status file does not
                # reset the authoritative idempotency journal or permit writes.
                pass

    @staticmethod
    def _timestamp():
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    def start(self, mode):
        now = self._timestamp()
        self.data["last_attempted_at"] = now
        self.data["last_run"] = {
            "mode": str(mode),
            "outcome": "running",
            "counts": {key: 0 for key in sorted(self.COUNT_KEYS)},
            "safe_error_codes": [],
            "lock_held": False,
            "started_at": now,
            "finished_at": None,
        }
        atomic_write_json(self.path, self.data)

    def finish(self, success, counts=None, error_codes=(), lock_held=False):
        run = self.data.get("last_run") or {}
        normalized_counts = {key: 0 for key in sorted(self.COUNT_KEYS)}
        for key, value in (counts or {}).items():
            if key in self.COUNT_KEYS:
                normalized_counts[key] = max(0, int(value))
        now = self._timestamp()
        run.update({
            "outcome": "success" if success else "failed",
            "counts": normalized_counts,
            "safe_error_codes": sorted({str(code) for code in error_codes if code}),
            "lock_held": bool(lock_held),
            "finished_at": now,
        })
        self.data["last_run"] = run
        if success:
            self.data["last_successful_at"] = now
        atomic_write_json(self.path, self.data)
