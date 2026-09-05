"""Private local runtime primitives for scheduled/offline-safe workflows."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import tempfile
import traceback
from pathlib import Path

from message_safety import opaque_id


LOCKED_EXIT_CODE = 75

# Diagnostics for a failed run. The status file stays a PII-free summary for
# casual viewing; this is the private trail for the case that summary cannot
# serve - an unattended run that failed with nothing else to go on.
FAILURE_LOG_NAME = "failures.log"
MAX_FAILURE_LOG_BYTES = 512 * 1024
MAX_DETAIL_CHARS = 4000

# Exception MESSAGES are the PII risk here, not the frames. A KeyError can
# carry a subject, an HttpError a URL with a message id, a ValueError an
# address. Frames themselves are source code and file paths, which are not
# message-derived, so they are kept verbatim - losing them would defeat the
# point of the log.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)
_SECRET_RE = re.compile(
    r"(?:ya29\.[A-Za-z0-9_.\-]{10,}"
    r"|GOCSPX-[A-Za-z0-9_\-]{10,}"
    r"|1//0[A-Za-z0-9_\-]{10,}"
    r"|(?i:bearer)\s+[A-Za-z0-9._\-]{10,})"
)


def scrub_diagnostic_text(text):
    """Remove the PII classes a traceback can carry, keeping it readable.

    Addresses become a stable opaque id so two occurrences can still be
    correlated without revealing who they are. Credential-shaped strings are
    dropped outright rather than hashed; nothing about them is worth keeping.
    """
    scrubbed = _SECRET_RE.sub("<redacted-credential>", str(text or ""))
    scrubbed = _EMAIL_RE.sub(
        lambda m: f"<address:{opaque_id(m.group(0).casefold(), 8)}>", scrubbed
    )
    return scrubbed


def failure_log_path(status_path):
    """The private diagnostic log that sits beside a run's status file."""
    return Path(status_path).with_name(FAILURE_LOG_NAME)


def record_failure_diagnostic(status_path, exc, *, mode="", exit_code=None,
                              now=None):
    """Append one scrubbed diagnostic entry for a failed run.

    Returns True when written. Never raises: this runs inside an exception
    handler, and a logging failure must not replace the original error.
    """
    try:
        path = failure_log_path(status_path)
        ensure_private_directory(path.parent)
        stamp = (now or dt.datetime.now(dt.timezone.utc)).isoformat(
            timespec="seconds"
        )
        detail = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        entry = (
            f"===== {stamp} mode={mode or 'unknown'} "
            f"exit={exit_code if exit_code is not None else 'n/a'} =====\n"
            f"exception: {type(exc).__name__}\n"
            f"message:   {_head_and_tail(scrub_diagnostic_text(exc))}\n"
            f"{_head_and_tail(scrub_diagnostic_text(detail))}\n"
        )
        _rotate_if_oversized(path)
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(entry)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
        return True
    except Exception:  # noqa: BLE001 - never mask the failure being recorded
        return False


def _head_and_tail(text, limit=MAX_DETAIL_CHARS):
    """Truncate from the middle, keeping both ends.

    A deep library stack buries the actual raise site at the BOTTOM, and our
    own frames sit at the top. Keeping only the head loses the cause; keeping
    only the tail loses which of our calls led there. The first real
    truncation proved it - a BrokenPipeError traceback was cut mid-frame in
    ssl.py, discarding exactly the line that raised.
    """
    text = str(text or "")
    if len(text) <= limit:
        return text
    keep = max(1, (limit - 40) // 2)
    omitted = len(text) - (keep * 2)
    return (
        text[:keep]
        + f"\n... [{omitted} characters omitted] ...\n"
        + text[-keep:]
    )


def _rotate_if_oversized(path):
    """Keep one previous generation so the log cannot grow without bound."""
    try:
        if path.exists() and path.stat().st_size >= MAX_FAILURE_LOG_BYTES:
            previous = path.with_suffix(path.suffix + ".1")
            os.replace(path, previous)
            os.chmod(previous, 0o600)
    except OSError:
        pass


def ensure_private_directory(path):
    """Create ``path`` privately, including every directory made on the way.

    ``mkdir(parents=True, mode=0o700)`` applies the mode to the LAST component
    only; intermediate directories are created with the process umask, which
    is 0755 in practice. A nested state_dir like ``triage-state/<account>``
    therefore produced a world-listable ``triage-state`` holding a private
    leaf, and the account names inside it were readable by any local user.

    Only directories this call creates are tightened. A pre-existing ancestor
    (the repo checkout, /tmp, a shared parent) is left alone: chmod on a
    directory the caller does not own raises EPERM, and its permissions were
    never this function's to decide.
    """
    directory = Path(path)
    created = []
    probe = directory
    while not probe.exists():
        created.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for made in created:
        os.chmod(made, 0o700)
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
        "skipped", "failures", "deferred_draft_limit",
        "deferred_write_limit",
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
