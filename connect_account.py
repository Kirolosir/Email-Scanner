"""Store a collected OAuth credential for the hosted connection.

The account is explicit, the token is encrypted through the configured KMS
provider, and the plaintext source is removed only after a successful store.
Cloud clients are imported lazily so tests remain offline.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import connection as conn
import connection_tokens as tokens
from connection_kms import KmsKeyProvider


KMS_KEY_ENV = "CONNECTION_KMS_KEY"

# Keys a token document might carry an address under. The current broker emits
# none of these; the check exists so that a future one which does is verified
# instead of believed.
ADDRESS_KEYS = ("email", "account", "email_address")

REQUIRED_TOKEN_FIELD = "refresh_token"


class ConnectAccountError(RuntimeError):
    """Never carries the token, or any part of it, in its message."""


# ---------------------------------------------------------------------
# Reading what the broker produced
# ---------------------------------------------------------------------

def read_token_document(path):
    """Load the collected credential, refusing anything unusable.

    Errors name the file, never its contents: a message that quoted the
    document to explain what was wrong with it would put a refresh token into
    a terminal scrollback and very likely a support thread.
    """
    try:
        with Path(path).open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError as exc:
        raise ConnectAccountError(f"no credential file at {path}") from exc
    except OSError as exc:
        raise ConnectAccountError(
            f"could not read {path} ({type(exc).__name__})"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ConnectAccountError(
            f"{path} is not valid JSON; collect it again"
        ) from exc

    if not isinstance(document, dict):
        raise ConnectAccountError(f"{path} does not contain an object")
    if not document.get(REQUIRED_TOKEN_FIELD):
        raise ConnectAccountError(
            f"{path} carries no {REQUIRED_TOKEN_FIELD}; a token that cannot "
            "be refreshed is no use to a scheduled run"
        )
    return document


def address_in_document(document):
    """Any address the document claims, or None.

    Returned rather than compared here so the caller decides what a mismatch
    means, and so the check is testable without a file.
    """
    for key in ADDRESS_KEYS:
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def check_account_agrees(document, account):
    """Refuse a document that names a different account than the operator did."""
    claimed = address_in_document(document)
    if claimed is None:
        return None
    if not conn.same_account(claimed, account):
        raise ConnectAccountError(
            "the credential names a different account than --account; "
            "refusing rather than connecting a mailbox nobody asked for"
        )
    return claimed


# ---------------------------------------------------------------------
# The KMS client, built only when actually asked for
# ---------------------------------------------------------------------

def default_kms_client():
    """Construct a real Cloud KMS client.

    The import lives here, not at module scope, so importing this module
    reaches nothing. This is the single place in the codebase that would open
    a connection to Google for key operations, and it runs only when a caller
    has supplied no factory of its own.
    """
    try:
        from google.cloud import kms  # noqa: PLC0415 - deliberately deferred
    except ImportError as exc:
        raise ConnectAccountError(
            "google-cloud-kms is not installed; install it on the deployment "
            "host, or pass a client factory"
        ) from exc
    return kms.KeyManagementServiceClient()


def build_provider(key_name, client_factory=None, crc32c=None):
    """A KmsKeyProvider for `key_name`, using injected parts if given.

    The checksum function is injectable alongside the client for the same
    reason: every KMS request carries a CRC32C of its payload, and a test
    should be able to exercise that without google-crc32c installed.
    """
    if not key_name:
        raise ConnectAccountError(
            f"{KMS_KEY_ENV} is not set; it names the Cloud KMS key that wraps "
            "the token's data key"
        )
    factory = client_factory or default_kms_client
    return KmsKeyProvider(key_name, factory(), crc32c=crc32c)


# ---------------------------------------------------------------------
# The operation
# ---------------------------------------------------------------------

def connect_token_document(root, account, document, provider, *,
                           timezone="UTC", run_at="18:00", now=None):
    """Establish a connection from an in-memory credential document.

    Order matters. The account is validated and occupancy checked first, but
    the record is only published after token encryption and storage succeeds.
    A failed KMS or filesystem write therefore leaves a vacant deployment
    vacant, and a failed reauthorisation leaves its prior record intact.
    """
    if not isinstance(document, dict) or not document.get(REQUIRED_TOKEN_FIELD):
        raise ConnectAccountError(
            "credential carries no refresh_token; a token that cannot be "
            "refreshed is no use to a scheduled run"
        )
    check_account_agrees(document, account)

    with conn.lifecycle_lock(root):
        existing = conn.current(root)
        connection = conn.prepare_connection(
            root, account, timezone=timezone, run_at=run_at, now=now
        )
        try:
            tokens.store_token(connection, document, provider)
        except tokens.TokenStoreError:
            raise
        except OSError as exc:
            raise ConnectAccountError(
                f"could not store the encrypted credential "
                f"({type(exc).__name__})"
            ) from exc

        try:
            conn.persist_connection(connection)
        except OSError as exc:
            # On a first connection there was no live token to preserve. Do
            # not leave a disconnected account's encrypted credential behind
            # if publishing the occupancy record failed.
            if existing is None:
                try:
                    removed = tokens.forget_token(connection)
                except OSError as cleanup_exc:
                    raise ConnectAccountError(
                        "could not publish the connection record, and cleanup "
                        "of the unpublished encrypted credential could not be "
                        f"confirmed ({type(cleanup_exc).__name__})"
                    ) from exc
                if not removed:
                    raise ConnectAccountError(
                        "could not publish the connection record, and cleanup "
                        "of the unpublished encrypted credential could not be "
                        "confirmed"
                    ) from exc
            raise ConnectAccountError(
                f"could not publish the connection record "
                f"({type(exc).__name__})"
            ) from exc

    return {
        "account": connection.account,
        "connected_at": connection.connected_at,
        "last_authorized_at": connection.last_authorized_at,
        "run_at": connection.run_at,
        "timezone": connection.timezone_name,
    }


def connect_account(root, account, token_path, provider, *, timezone="UTC",
                    run_at="18:00", now=None, destroy_token_file=True):
    """Connect from a broker file, deleting its plaintext only on success."""
    document = read_token_document(token_path)
    summary = connect_token_document(
        root, account, document, provider,
        timezone=timezone, run_at=run_at, now=now,
    )
    # Drop the plaintext reference before touching the filesystem again.
    document = None

    destroyed = False
    if destroy_token_file:
        try:
            os.unlink(token_path)
            destroyed = True
        except OSError:
            destroyed = False

    return {**summary, "token_file_destroyed": destroyed}


def schedule_conflict(root, timezone, run_at, provided):
    """What a re-authorisation will silently ignore, if anything.

    connect() preserves the schedule of an existing connection on purpose: a
    weekly token refresh must not change how the deployment behaves. That is
    right, and it means a --run-at passed out of habit does nothing. Silently
    ignored input is its own bug, so the caller is told.
    """
    existing = conn.current(root)
    if existing is None:
        return []
    ignored = []
    if "timezone" in provided and timezone != existing.timezone_name:
        ignored.append(f"timezone ({existing.timezone_name} kept)")
    if "run_at" in provided and run_at != existing.run_at:
        ignored.append(f"run_at ({existing.run_at} kept)")
    return ignored


# ---------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Connect a collected credential to this deployment.",
    )
    parser.add_argument("--root", required=True,
                        help="deployment state root (HOSTED_STATE_ROOT)")
    parser.add_argument("--account", required=True,
                        help="the address this credential belongs to; asserted "
                             "by you and not verifiable from the token")
    parser.add_argument("--token", required=True,
                        help="credential file written by broker_client collect")
    parser.add_argument("--kms-key", default=os.environ.get(KMS_KEY_ENV, ""),
                        help=f"Cloud KMS key name (default: ${KMS_KEY_ENV})")
    parser.add_argument("--timezone", default="UTC")
    parser.add_argument("--run-at", default="18:00")
    parser.add_argument("--keep-token-file", action="store_true",
                        help="do not delete the plaintext credential afterwards")
    parser.add_argument("--yes", action="store_true",
                        help="required; connecting decides whose mailbox this "
                             "deployment opens")
    return parser, parser.parse_args(argv)


def main(argv=None, *, client_factory=None, crc32c=None):
    parser, args = parse_args(argv)

    # Which schedule flags were actually typed, so an ignored one can be
    # reported without guessing from a default that happens to match.
    argv_list = list(sys.argv[1:] if argv is None else argv)
    provided = {name for name, flag in
                (("timezone", "--timezone"), ("run_at", "--run-at"))
                if flag in argv_list}

    if not args.yes:
        parser.error(
            "refusing without --yes: connecting decides whose mailbox this "
            "deployment opens at its scheduled time"
        )

    try:
        for note in schedule_conflict(args.root, args.timezone, args.run_at,
                                      provided):
            print(f"note: re-authorisation does not change {note}",
                  file=sys.stderr)

        provider = build_provider(args.kms_key,
                                  client_factory=client_factory,
                                  crc32c=crc32c)
        summary = connect_account(
            args.root, args.account, args.token, provider,
            timezone=args.timezone, run_at=args.run_at,
            destroy_token_file=not args.keep_token_file,
        )
    except conn.ConnectionOccupied as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except (ConnectAccountError, conn.ConnectionConfigError,
            tokens.TokenStoreError) as exc:
        print(f"failed: {exc}", file=sys.stderr)
        print(f"the credential file at {args.token} has been left in place",
              file=sys.stderr)
        return 1

    print(f"connected {summary['account']}")
    print(f"  schedule   {summary['run_at']} {summary['timezone']}")
    print(f"  authorized {summary['last_authorized_at']}")
    if summary["token_file_destroyed"]:
        print("  plaintext credential destroyed")
    else:
        print(f"  plaintext credential STILL AT {args.token} - remove it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
