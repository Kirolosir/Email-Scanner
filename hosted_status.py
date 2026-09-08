"""The hosted deployment's status surface. Read-only, by construction.

WHY THIS SERVES NOTHING MUTABLE. oauth_broker.py already fixed this boundary
for invites: "Nothing reachable over the network can create an invite. Adding
one means editing this variable and restarting the instance." The same
reasoning applies harder to the connection lifecycle. Disconnecting destroys a
credential and archives somebody's journal; connecting decides whose mailbox
this deployment opens at 6pm. Neither belongs behind an HTTP handler on the
public internet, however well authenticated. Those stay operator acts run
against the instance deliberately. This module answers two questions and
changes nothing.

WHY JSON AND NOT A PAGE. web_status.py is the human interface and it stays
where it is - bound to 127.0.0.1, reachable only by the person at the machine.
This is a different thing: an operator endpoint on a server nobody is sitting
at. Returning JSON means there is no markup to escape and therefore no way to
get an injection wrong, and it is what a health check or an alerting rule
actually wants to read.

WHY IT STILL AUTHENTICATES ON A PRIVATE PORT. The deployment binds this to
loopback on a single VM and reaches it through an SSH tunnel, so there is no
public listener at all. The bearer and the forwarded-https check remain
because the binding is a deployment choice and this module cannot verify it:
if the service is ever put behind a load balancer, the code must not be the
part that has to change. Defence that only works while a config file says so
is not defence.

WHY NO ADDRESS APPEARS. The local page may show the connected address; the
person reading it already knows it. A response from here can be logged,
forwarded, or piped into a monitoring system, so it must not disclose who uses
the system. The opaque connection id says whether a connection exists without
saying whose it is. Configuration - schedule, timezone, limits - carries no
such risk and is included, because verifying a deploy without it means
guessing.

WHY IT CANNOT REACH A TOKEN. This module deliberately imports neither
connection_tokens nor connection_kms nor anything in the Gmail stack. A
compromise of this endpoint yields status, not mail: there is no code path
from here to a decrypted credential, and a guard asserts the imports stay that
way rather than trusting the intention.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

import connection as conn
import connection_expiry as expiry


MIN_BEARER_CHARS = 32
JSON = [("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff")]

HEALTH_PATH = "/healthz"
STATUS_PATH = "/"

STATUS_FILE = "daily-status.json"


class HostedConfigError(RuntimeError):
    """Raised when the deployment is not safely configured.

    Raised at boot, never at request time, so a misconfigured instance fails
    to start rather than serving something weaker than intended.
    """


# ---------------------------------------------------------------------
# The state volume has to be a real filesystem
# ---------------------------------------------------------------------

def verify_durable_state_root(root, *, require_mountpoint=False):
    """Prove the volume supports what the state layer actually relies on.

    This is not defensive decoration. The whole connection lifecycle is built
    on two POSIX primitives: atomic_write_json uses os.replace, and
    ExclusiveRunLock uses fcntl.flock. A GCS-FUSE mount supports neither
    reliably and a container's own writable layer is discarded on recycle, so
    deploying onto either loses the connection record, the journal and the
    archive - silently, and looking exactly like a deployment that simply had
    nothing in it.

    require_mountpoint covers the failure that only appears on a VM. There,
    an unmounted disk does NOT make the path disappear: the mountpoint
    directory still exists on the boot disk, is ext4, and passes both probes
    below perfectly. The service would run, write a real connection record to
    the wrong disk, and lose it the moment the intended disk was mounted over
    the top. Checking that the path is genuinely a mount point is the only
    thing that distinguishes those two cases from inside the process, and it
    is off by default because a local checkout and a test directory are
    legitimately not mount points.

    Probing at boot converts all of this into a refusal to start. It costs one
    temporary file.
    """
    root = Path(root)
    if not root.is_dir():
        raise HostedConfigError(
            "HOSTED_STATE_ROOT is not an existing directory. Create the "
            "directory and mount a durable POSIX volume on it"
        )

    if require_mountpoint and not os.path.ismount(root):
        raise HostedConfigError(
            "HOSTED_STATE_ROOT is a directory but nothing is mounted on it. "
            "It is on the boot disk, so state written there would be lost "
            "the moment the real volume is mounted over it. Mount the disk, "
            "or set HOSTED_REQUIRE_MOUNTPOINT=false if this path is "
            "deliberately not a separate volume"
        )

    descriptor, temporary = None, None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".probe.", dir=root)
    except OSError as exc:
        raise HostedConfigError(
            f"HOSTED_STATE_ROOT is not writable ({type(exc).__name__})"
        ) from exc

    try:
        try:
            # Acquire only. Closing the descriptor below releases the lock,
            # so an explicit LOCK_UN would be a line no test could justify.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise HostedConfigError(
                "HOSTED_STATE_ROOT does not support advisory file locking, "
                "which the run lease requires. A GCS-FUSE mount cannot "
                "provide it; use a real POSIX volume"
            ) from exc

        os.close(descriptor)
        descriptor = None
        destination = root / ".probe.rename"
        try:
            os.replace(temporary, destination)
            temporary = str(destination)
        except OSError as exc:
            raise HostedConfigError(
                "HOSTED_STATE_ROOT does not support atomic rename, which "
                "every state write requires. Use a real POSIX volume"
            ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    return True


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

class HostedConfig:
    """Environment-derived configuration. The bearer never leaves this object."""

    def __init__(self, state_root, operator_bearer, *,
                 require_forwarded_https=True, require_mountpoint=True,
                 verify_root=True):
        if not state_root:
            raise HostedConfigError("HOSTED_STATE_ROOT is required")
        if len(operator_bearer or "") < MIN_BEARER_CHARS:
            raise HostedConfigError(
                f"HOSTED_OPERATOR_BEARER must be at least {MIN_BEARER_CHARS} "
                "characters"
            )
        self.state_root = Path(state_root)
        self._operator_bearer = operator_bearer
        self.require_forwarded_https = require_forwarded_https
        self.require_mountpoint = require_mountpoint
        if verify_root:
            verify_durable_state_root(
                self.state_root, require_mountpoint=require_mountpoint
            )

    def bearer_matches(self, presented):
        return hmac.compare_digest(self._operator_bearer, presented or "")

    @staticmethod
    def _clean(raw):
        """Strip what a value picks up crossing a hosting dashboard."""
        value = (raw or "").strip()
        for quote in ('"', "'"):
            if len(value) >= 2 and value.startswith(quote) and \
                    value.endswith(quote):
                value = value[1:-1].strip()
        return value

    @staticmethod
    def _is_false(value):
        """Both switches default ON. Only an explicit denial turns one off."""
        return value.strip().lower() in {"false", "0", "no"}

    @classmethod
    def from_environment(cls, env=None, *, verify_root=True):
        env = env if env is not None else os.environ
        return cls(
            cls._clean(env.get("HOSTED_STATE_ROOT", "")),
            cls._clean(env.get("HOSTED_OPERATOR_BEARER", "")),
            require_forwarded_https=not cls._is_false(
                cls._clean(env.get("HOSTED_REQUIRE_FORWARDED_HTTPS", "true"))
            ),
            require_mountpoint=not cls._is_false(
                cls._clean(env.get("HOSTED_REQUIRE_MOUNTPOINT", "true"))
            ),
            verify_root=verify_root,
        )


# ---------------------------------------------------------------------
# Reading state
# ---------------------------------------------------------------------

def _read_json(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _last_run(status_document):
    """The last run's outcome, with no counts and no message detail."""
    if not status_document:
        return None
    return {
        "outcome": str(status_document.get("outcome") or "unknown"),
        "finished_at": str(status_document.get("finished_at") or ""),
    }


def _last_successful_run(status_document):
    """Only a success is evidence a token still worked."""
    if not status_document or status_document.get("outcome") != "success":
        return None
    stamp = status_document.get("finished_at")
    return stamp if isinstance(stamp, str) and stamp.strip() else None


def status_document(state_root, now=None):
    """The whole response body. Contains no address and no message content."""
    now = now or dt.datetime.now(dt.timezone.utc)
    body = {
        "generated_at": now.isoformat(timespec="seconds"),
        "connection": {"state": "vacant"},
    }

    try:
        connection = conn.current(state_root)
    except conn.ConnectionConfigError as exc:
        # A damaged record must not read as "nobody is connected", for the
        # same reason connection.current() refuses to: that is how a takeover
        # goes unnoticed.
        body["connection"] = {
            "state": "unreadable",
            "detail": f"connection record is unusable ({type(exc).__name__})",
        }
        return body

    if connection is None:
        return body

    document = _read_json(Path(connection.directory) / STATUS_FILE)
    body["connection"] = {
        "state": "connected",
        # The opaque id, never the address.
        "id": connection.id,
        "connected_at": connection.connected_at,
        "last_authorized_at": connection.last_authorized_at,
        "enabled": connection.enabled,
        "timezone": connection.timezone_name,
        "run_at": connection.run_at,
        "limits": {
            "max_scan": connection.max_scan,
            "limit": connection.limit,
            "max_drafts": connection.max_drafts,
        },
    }
    body["expiry"] = expiry.expiry_state(
        connection, now, last_successful_run=_last_successful_run(document)
    )
    body["last_run"] = _last_run(document)
    return body


# ---------------------------------------------------------------------
# The application
# ---------------------------------------------------------------------

class HostedStatusApp:
    """WSGI application. Every handler is a read."""

    def __init__(self, config, clock=None):
        self.config = config
        # Injected so tests never depend on the wall clock.
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _respond(start_response, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = list(JSON) + [("Content-Length", str(len(body)))]
        start_response(status, headers)
        return [body]

    def _bearer_ok(self, environ):
        header = environ.get("HTTP_AUTHORIZATION", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer":
            # Still compare, so a missing header and a wrong token take the
            # same time and neither is distinguishable by timing.
            self.config.bearer_matches("")
            return False
        return self.config.bearer_matches(presented.strip())

    def _https_ok(self, environ):
        if not self.config.require_forwarded_https:
            return True
        # Cloud Run terminates TLS and sets this. Trusting a forwarded header
        # is only safe behind a proxy that always overwrites it, which is why
        # this is a setting and not an assumption.
        forwarded = environ.get("HTTP_X_FORWARDED_PROTO", "")
        return forwarded.split(",")[0].strip().lower() == "https"

    # -- routes -------------------------------------------------------

    def __call__(self, environ, start_response):
        try:
            return self._route(environ, start_response)
        except Exception:  # noqa: BLE001 - nothing escapes as a traceback
            # A traceback in a response body names paths and code. The detail
            # belongs in the instance's own logs, which the platform captures
            # from stderr, not in something a caller can read.
            return self._respond(start_response, "500 Internal Server Error",
                                 {"error": "internal error"})

    def _route(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "") or "/"

        if method not in {"GET", "HEAD"}:
            # There is no mutating verb to reach, but saying so plainly is
            # better than a 404 that reads like a missing route.
            return self._respond(start_response, "405 Method Not Allowed",
                                 {"error": "this service is read-only"})

        if path == HEALTH_PATH:
            # Unauthenticated on purpose: a platform health check has no
            # credential. It therefore discloses nothing but liveness - not
            # whether a connection exists, not the configuration.
            return self._respond(start_response, "200 OK", {"status": "ok"})

        if path != STATUS_PATH:
            return self._respond(start_response, "404 Not Found",
                                 {"error": "no such route"})

        if not self._https_ok(environ):
            return self._respond(start_response, "400 Bad Request",
                                 {"error": "https required"})

        if not self._bearer_ok(environ):
            headers = list(JSON) + [("WWW-Authenticate", "Bearer")]
            body = json.dumps({"error": "unauthorized"}).encode("utf-8")
            headers.append(("Content-Length", str(len(body))))
            start_response("401 Unauthorized", headers)
            return [body]

        return self._respond(
            start_response, "200 OK",
            status_document(self.config.state_root, self.clock()),
        )


# ---------------------------------------------------------------------
# Checking a volume before anything is entrusted to it
# ---------------------------------------------------------------------

def main(argv=None):
    """Verify a state root from the command line, before connecting anything.

    The deployment runbook needs a way to prove a freshly formatted and
    mounted disk actually supports what the lifecycle relies on, at the point
    where the answer is still cheap to act on. Reasoning that ext4 on a
    persistent disk provides atomic rename and advisory locking is correct but
    it is reasoning; this runs the same probe the service runs at boot and
    says so out loud.

    Exits nonzero on an unsuitable volume so it can gate a deploy script.
    """
    parser = argparse.ArgumentParser(
        description="Check that a directory can hold the connection state.",
    )
    parser.add_argument(
        "--check-state-root", required=True, metavar="PATH",
        help="directory to probe for atomic rename and advisory locking",
    )
    parser.add_argument(
        "--require-mountpoint", action="store_true",
        help="also require that a volume is actually mounted there, which is "
             "what distinguishes a mounted disk from an empty directory "
             "sitting on the boot disk",
    )
    args = parser.parse_args(argv)

    target = args.check_state_root
    try:
        verify_durable_state_root(
            target, require_mountpoint=args.require_mountpoint
        )
    except HostedConfigError as exc:
        print(f"UNSUITABLE: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {target} supports atomic rename and advisory locking")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
