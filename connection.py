"""Single-account connection state with atomic lifecycle operations.

The connection record owns the slot even if authorization expires. The same
account may reconnect without losing settings; a different account must wait
for an explicit disconnect.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import account_profile
from private_runtime import atomic_write_json, ensure_private_directory


CONNECTION_FILE = "connection.json"
ACTIVE_DIR = "active"
RECORD_VERSION = 1

EMAIL_SHAPED = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
RUN_AT = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

ALLOWED_KEYS = frozenset({
    "version", "account", "timezone", "run_at", "connected_at",
    "last_authorized_at", "enabled", "max_scan", "limit", "max_drafts",
})

DEFAULT_LIMITS = {"max_scan": 25, "limit": 125, "max_drafts": 25}
DEFAULT_TIMEZONE = account_profile.LEGACY_PROFILE.timezone


class ConnectionError(RuntimeError):
    pass


class ConnectionOccupied(ConnectionError):
    """A different account already holds the connection.

    Carries the occupant so the caller can say who to disconnect, rather than
    making somebody go and look.
    """

    def __init__(self, account):
        self.account = account
        super().__init__(
            f"{account} is already connected. Disconnect it first; "
            "connecting a different account never replaces one silently."
        )


class ConnectionConfigError(ValueError):
    pass


class ConnectionBusy(ConnectionError):
    """Another lifecycle operation currently owns the connection."""


@contextmanager
def lifecycle_lock(root, *, blocking=True):
    """Serialize connection, settings, disconnect, and scheduled-run changes.

    A directory descriptor can be flocked without creating a lock artifact,
    so even an operation that is refused still writes nothing. The state root
    is required to exist before a hosted lifecycle operation begins.
    """
    try:
        descriptor = os.open(Path(root), os.O_RDONLY)
    except OSError as exc:
        raise ConnectionConfigError(
            f"connection state cannot be locked ({type(exc).__name__})"
        ) from exc
    try:
        operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(descriptor, operation)
        except BlockingIOError as exc:
            raise ConnectionBusy("the connected account is currently busy") from exc
        yield
    finally:
        os.close(descriptor)


def normalize_account(value):
    """One spelling for comparison. Case and surrounding space never differ."""
    return str(value or "").strip().casefold()


def same_account(left, right):
    return bool(left) and normalize_account(left) == normalize_account(right)


def _require(condition, message):
    if not condition:
        raise ConnectionConfigError(message)


class Connection:
    """The connected account plus the paths derived from a fixed root.

    Paths are derived from the root and a constant directory name, never from
    the account address, so there is no value from outside that can steer
    where anything is written.
    """

    def __init__(self, document, root):
        self.root = Path(root).resolve()
        self.account = document["account"]
        self.timezone_name = document["timezone"]
        self.timezone = ZoneInfo(self.timezone_name)
        self.run_at = document["run_at"]
        self.connected_at = document.get("connected_at", "")
        self.last_authorized_at = document.get("last_authorized_at", "")
        self.enabled = bool(document.get("enabled", True))
        # Written out rather than looped over. A computed attribute name is
        # not statically auditable, and the no-send audit rightly refuses to
        # let production code reach an attribute it cannot name.
        self.max_scan = int(document.get("max_scan", DEFAULT_LIMITS["max_scan"]))
        self.limit = int(document.get("limit", DEFAULT_LIMITS["limit"]))
        self.max_drafts = int(
            document.get("max_drafts", DEFAULT_LIMITS["max_drafts"])
        )

    # -- scheduling shape, unchanged from the single-operator system ----

    @property
    def hour(self):
        return int(self.run_at.split(":")[0])

    @property
    def minute(self):
        return int(self.run_at.split(":")[1])

    # -- derived layout -------------------------------------------------

    @property
    def id(self):
        """A stable label for lease keys and log lines, never the address."""
        return "active"

    @property
    def directory(self):
        return self.root / ACTIVE_DIR

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

    def as_document(self):
        return {
            "version": RECORD_VERSION,
            "account": self.account,
            "timezone": self.timezone_name,
            "run_at": self.run_at,
            "connected_at": self.connected_at,
            "last_authorized_at": self.last_authorized_at,
            "enabled": self.enabled,
            "max_scan": self.max_scan,
            "limit": self.limit,
            "max_drafts": self.max_drafts,
        }

    def __repr__(self):
        return f"<Connection {self.account} {self.run_at} {self.timezone_name}>"


def record_path(root):
    return Path(root) / CONNECTION_FILE


def _validate(document):
    _require(isinstance(document, dict), "connection record must be an object")
    unexpected = sorted(set(document) - ALLOWED_KEYS)
    _require(not unexpected,
             f"unsupported connection keys: {', '.join(unexpected)}")
    _require(document.get("version") == RECORD_VERSION,
             "connection record must be a version 1 object")

    account = document.get("account")
    _require(isinstance(account, str) and EMAIL_SHAPED.match(account.strip()),
             "connection record has an invalid account address")

    _require(isinstance(document.get("run_at"), str)
             and RUN_AT.match(document["run_at"]),
             "run_at must be HH:MM in 24-hour local time")

    timezone_name = document.get("timezone")
    _require(isinstance(timezone_name, str) and timezone_name.strip(),
             "connection record must name a timezone")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConnectionConfigError(
            f"unknown timezone {timezone_name!r}"
        ) from exc

    for key in DEFAULT_LIMITS:
        if key in document:
            value = document[key]
            _require(isinstance(value, int) and not isinstance(value, bool)
                     and value >= 0,
                     f"{key} must be a nonnegative integer")

    if "enabled" in document:
        _require(isinstance(document["enabled"], bool),
                 "enabled must be true or false")


def current(root):
    """The connection this deployment holds, or None if vacant.

    A record that cannot be validated raises rather than reading as vacant:
    treating an unparseable record as "nobody is connected" is how a different
    account would end up quietly taking over a damaged deployment.
    """
    path = record_path(root)
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConnectionConfigError(
            f"connection record is unreadable: {type(exc).__name__}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ConnectionConfigError(
            "connection record is not valid JSON"
        ) from exc

    _validate(document)
    return Connection(document, root)


def occupied_by(root):
    """The connected address, or None. Never raises for a vacant deployment."""
    connection = current(root)
    return connection.account if connection else None


def prepare_connection(root, account, *, timezone=DEFAULT_TIMEZONE,
                       run_at="18:00",
                       now=None, limits=None):
    """Build the connection record that ``connect`` would persist.

    This is deliberately side-effect free. A caller that also has to store a
    credential can prepare the record, finish the fallible encryption step,
    and only then make the connection visible. Marking the deployment
    occupied before its credential exists creates a connected-looking account
    that can never run.

    Vacant            -> connect, recording both timestamps.
    Same account      -> a re-authorisation. Only last_authorized_at moves;
                         schedule, limits and every artifact are untouched,
                         because a weekly token refresh must not quietly
                         change how the deployment behaves.
    Different account -> ConnectionOccupied, having written nothing.
    """
    account = str(account or "").strip()
    _require(EMAIL_SHAPED.match(account), "account address is not valid")
    stamp = (now or dt.datetime.now(dt.timezone.utc)).isoformat(
        timespec="seconds"
    )

    existing = current(root)
    if existing is not None:
        if not same_account(existing.account, account):
            # Deliberately before any write: a refusal leaves the deployment
            # exactly as it was found.
            raise ConnectionOccupied(existing.account)
        document = existing.as_document()
        document["last_authorized_at"] = stamp
        _validate(document)
        return Connection(document, root)

    document = {
        "version": RECORD_VERSION,
        "account": account,
        "timezone": timezone,
        "run_at": run_at,
        "connected_at": stamp,
        "last_authorized_at": stamp,
        "enabled": True,
        **DEFAULT_LIMITS,
        **(limits or {}),
    }
    _validate(document)
    return Connection(document, root)


def persist_connection(connection):
    """Atomically publish one already-validated connection record."""
    root = connection.root
    _validate(connection.as_document())
    ensure_private_directory(root)
    ensure_private_directory(connection.directory)
    atomic_write_json(record_path(root), connection.as_document())
    return connection


def connect(root, account, *, timezone=DEFAULT_TIMEZONE, run_at="18:00", now=None,
            limits=None):
    """Establish or refresh the single connection.

    Callers that also store a token should use ``prepare_connection`` and
    ``persist_connection`` so the token can be committed first. This compact
    wrapper preserves the original API for connection-only callers.
    """
    connection = prepare_connection(
        root, account, timezone=timezone, run_at=run_at, now=now,
        limits=limits,
    )
    return persist_connection(connection)


def update_settings(root, account, *, timezone=None, run_at=None,
                    enabled=None, limits=None):
    """Update the connected account's schedule and bounded run limits.

    Identity and authorization timestamps are never accepted from the caller.
    The account must already hold the connection, so a settings request cannot
    create or take over occupancy.
    """
    existing = current(root)
    if existing is None:
        raise ConnectionConfigError("no account is connected")
    if not same_account(existing.account, account):
        raise ConnectionOccupied(existing.account)
    document = existing.as_document()
    if timezone is not None:
        document["timezone"] = str(timezone).strip()
    if run_at is not None:
        document["run_at"] = str(run_at).strip()
    if enabled is not None:
        document["enabled"] = enabled
    for key, value in dict(limits or {}).items():
        _require(key in DEFAULT_LIMITS, f"unsupported limit {key!r}")
        document[key] = value
    _validate(document)
    return persist_connection(Connection(document, root))
