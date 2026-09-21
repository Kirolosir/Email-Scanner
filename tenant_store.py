"""PostgreSQL persistence for users, mailbox ownership, sessions, and jobs."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mailbox_tokens import EncryptedMailboxToken, seal_mailbox_token


SESSION_BYTES = 32
CSRF_BYTES = 32
SESSION_TTL = dt.timedelta(days=30)
ALLOWED_JOB_KINDS = frozenset({"incoming", "daily", "backfill", "undo"})


class TenantStoreError(RuntimeError):
    """A persistence failure safe to surface without database detail."""


class TenantAccessDenied(TenantStoreError):
    """The requested object does not belong to the signed-in user."""


@dataclass(frozen=True)
class SessionIdentity:
    session_id: uuid.UUID
    user_id: uuid.UUID
    display_email: str
    csrf_secret: bytes
    expires_at: dt.datetime


@dataclass(frozen=True)
class IssuedSession:
    token: str
    identity: SessionIdentity


@dataclass(frozen=True)
class Mailbox:
    id: uuid.UUID
    user_id: uuid.UUID
    google_subject: str
    address: str
    disconnected_at: dt.datetime | None


@dataclass(frozen=True)
class ClaimedJob:
    id: uuid.UUID
    mailbox_id: uuid.UUID
    kind: str
    requested_count: int | None
    processed_count: int
    group_size: int
    attempt_number: int


@dataclass(frozen=True)
class MailboxView:
    id: uuid.UUID
    address: str
    timezone: str
    run_at: dt.time
    enabled: bool
    next_run_at: dt.datetime | None
    last_job_status: str | None
    processed_count: int
    requested_count: int | None


def _utc_now():
    return dt.datetime.now(dt.timezone.utc)


def next_scheduled_run(timezone_name, run_at, after):
    """Return the first configured local run strictly after ``after``."""
    try:
        timezone = ZoneInfo(str(timezone_name))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise TenantStoreError("mailbox timezone is invalid") from exc
    if not isinstance(run_at, dt.time):
        raise TenantStoreError("mailbox run time is invalid")
    if after.tzinfo is None:
        raise TenantStoreError("scheduler time must include a timezone")
    local = after.astimezone(timezone)
    target = dt.datetime.combine(local.date(), run_at, tzinfo=timezone)
    if target <= local:
        target = dt.datetime.combine(
            local.date() + dt.timedelta(days=1), run_at, tzinfo=timezone
        )
    return target.astimezone(dt.timezone.utc)


def session_token_hash(token):
    """Hash a high-entropy bearer before it reaches persistent storage."""
    try:
        raw = bytes.fromhex(str(token or ""))
    except ValueError as exc:
        raise TenantAccessDenied("invalid session") from exc
    if len(raw) != SESSION_BYTES:
        raise TenantAccessDenied("invalid session")
    return hashlib.sha256(raw).digest()


def csrf_value(identity):
    """Derive a request token from the per-session secret."""
    return hmac.new(
        identity.csrf_secret,
        b"email-scanner-dashboard-csrf-v2",
        hashlib.sha256,
    ).hexdigest()


class PostgresTenantStore:
    """Small transaction boundary around tenant-owned database records.

    The supplied connection follows the Python DB-API context-manager shape.
    psycopg is imported only by ``connect`` so offline tools can import this
    module without database client libraries installed.
    """

    def __init__(self, database):
        self.database = database

    @classmethod
    def connect(cls, database_url):
        if not str(database_url or "").startswith(("postgresql://", "postgres://")):
            raise TenantStoreError("DATABASE_URL must use PostgreSQL")
        try:
            import psycopg  # noqa: PLC0415 - optional outside hosted mode
        except ImportError as exc:
            raise TenantStoreError("PostgreSQL client support is unavailable") from exc
        try:
            return cls(psycopg.connect(database_url))
        except Exception as exc:  # noqa: BLE001 - hide credentials and host detail
            raise TenantStoreError("PostgreSQL connection failed") from exc

    def close(self):
        self.database.close()

    def create_or_get_user(self, issuer, subject, display_email):
        user_id = uuid.uuid4()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (id, identity_issuer, identity_subject, display_email)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (identity_issuer, identity_subject) DO UPDATE
                    SET display_email = EXCLUDED.display_email
                    RETURNING id
                    """,
                    (user_id, str(issuer), str(subject), str(display_email)),
                )
                return cursor.fetchone()[0]

    def issue_session(self, user_id, *, now=None, ttl=SESSION_TTL):
        now = now or _utc_now()
        session_id = uuid.uuid4()
        token = secrets.token_hex(SESSION_BYTES)
        secret = secrets.token_bytes(CSRF_BYTES)
        expires_at = now + ttl
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    WITH owner AS (
                        SELECT id, display_email FROM users
                        WHERE id = %s AND disabled_at IS NULL
                    )
                    INSERT INTO sessions
                        (id, user_id, token_hash, csrf_secret, created_at,
                         expires_at, last_seen_at)
                    SELECT %s, owner.id, %s, %s, %s, %s, %s FROM owner
                    RETURNING (SELECT display_email FROM owner)
                    """,
                    (user_id, session_id, session_token_hash(token), secret,
                     now, expires_at, now),
                )
                row = cursor.fetchone()
                if row is None or not row[0]:
                    raise TenantStoreError("session owner does not exist")
        return IssuedSession(
            token,
            SessionIdentity(session_id, user_id, row[0], secret, expires_at),
        )

    def authenticate_session(self, token, *, now=None):
        now = now or _utc_now()
        digest = session_token_hash(token)
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE sessions AS s
                    SET last_seen_at = %s
                    FROM users AS u
                    WHERE s.token_hash = %s
                      AND s.user_id = u.id
                      AND s.revoked_at IS NULL
                      AND s.expires_at > %s
                      AND u.disabled_at IS NULL
                    RETURNING s.id, s.user_id, u.display_email,
                              s.csrf_secret, s.expires_at
                    """,
                    (now, digest, now),
                )
                row = cursor.fetchone()
        if row is None:
            raise TenantAccessDenied("invalid session")
        return SessionIdentity(*row)

    def revoke_session(self, session_id, user_id, *, now=None):
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE sessions SET revoked_at = %s
                    WHERE id = %s AND user_id = %s AND revoked_at IS NULL
                    """,
                    (now or _utc_now(), session_id, user_id),
                )
                return cursor.rowcount == 1

    def upsert_mailbox(self, user_id, google_subject, address, *, now=None):
        now = now or _utc_now()
        mailbox_id = uuid.uuid4()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO mailboxes
                        (id, user_id, google_subject, address,
                         connected_at, last_authorized_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (google_subject) DO UPDATE
                    SET last_authorized_at = EXCLUDED.last_authorized_at,
                        address = EXCLUDED.address,
                        disconnected_at = NULL
                    WHERE mailboxes.user_id = EXCLUDED.user_id
                    RETURNING id, user_id, google_subject, address, disconnected_at
                    """,
                    (mailbox_id, user_id, str(google_subject), str(address), now, now),
                )
                row = cursor.fetchone()
                if row is None:
                    raise TenantAccessDenied("Gmail account belongs to another user")
                cursor.execute(
                    """
                    INSERT INTO mailbox_settings (mailbox_id, next_run_at)
                    VALUES (%s, %s) ON CONFLICT (mailbox_id) DO UPDATE
                    SET next_run_at = COALESCE(
                        mailbox_settings.next_run_at, EXCLUDED.next_run_at
                    )
                    """,
                    (row[0], next_scheduled_run(
                        "UTC", dt.time(18, 0), now
                    )),
                )
        return Mailbox(*row)

    def connect_mailbox(self, user_id, google_subject, address, token_document,
                        provider, *, now=None):
        """Atomically publish a mailbox and its mailbox-bound credential.

        The subject-scoped advisory lock prevents two callbacks for the same
        Google account from choosing different UUIDs. Encryption happens while
        the lock is held so the credential AAD always matches the committed
        mailbox UUID; the mailbox is never visible without its credential.
        """
        now = now or _utc_now()
        proposed_id = uuid.uuid4()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (str(google_subject),),
                )
                cursor.execute(
                    """
                    SELECT id, user_id FROM mailboxes WHERE google_subject = %s
                    """,
                    (str(google_subject),),
                )
                existing = cursor.fetchone()
                if existing is not None and existing[1] != user_id:
                    raise TenantAccessDenied(
                        "Gmail account belongs to another user"
                    )
                mailbox_id = existing[0] if existing is not None else proposed_id
                record = seal_mailbox_token(
                    mailbox_id, token_document, provider
                )
                cursor.execute(
                    """
                    INSERT INTO mailboxes
                        (id, user_id, google_subject, address,
                         connected_at, last_authorized_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (google_subject) DO UPDATE
                    SET last_authorized_at = EXCLUDED.last_authorized_at,
                        address = EXCLUDED.address,
                        disconnected_at = NULL
                    WHERE mailboxes.user_id = EXCLUDED.user_id
                    RETURNING id, user_id, google_subject, address, disconnected_at
                    """,
                    (mailbox_id, user_id, str(google_subject), str(address),
                     now, now),
                )
                row = cursor.fetchone()
                if row is None:
                    raise TenantAccessDenied(
                        "Gmail account belongs to another user"
                    )
                cursor.execute(
                    """
                    INSERT INTO oauth_credentials
                        (mailbox_id, version, wrapped_key, nonce, ciphertext,
                         updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (mailbox_id) DO UPDATE
                    SET version = EXCLUDED.version,
                        wrapped_key = EXCLUDED.wrapped_key,
                        nonce = EXCLUDED.nonce,
                        ciphertext = EXCLUDED.ciphertext,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (row[0], record.version, record.wrapped_key, record.nonce,
                     record.ciphertext, now),
                )
                cursor.execute(
                    """
                    INSERT INTO mailbox_settings (mailbox_id, next_run_at)
                    VALUES (%s, %s) ON CONFLICT (mailbox_id) DO UPDATE
                    SET next_run_at = COALESCE(
                        mailbox_settings.next_run_at, EXCLUDED.next_run_at
                    )
                    """,
                    (row[0], next_scheduled_run(
                        "UTC", dt.time(18, 0), now
                    )),
                )
        return Mailbox(*row)

    def store_credentials(self, user_id, mailbox_id, record):
        if not isinstance(record, EncryptedMailboxToken) or record.version != 1:
            raise TenantStoreError("encrypted credential is invalid")
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO oauth_credentials
                        (mailbox_id, version, wrapped_key, nonce, ciphertext,
                         updated_at)
                    SELECT m.id, %s, %s, %s, %s, %s
                    FROM mailboxes AS m
                    WHERE m.id = %s AND m.user_id = %s
                      AND m.disconnected_at IS NULL
                    ON CONFLICT (mailbox_id) DO UPDATE
                    SET version = EXCLUDED.version,
                        wrapped_key = EXCLUDED.wrapped_key,
                        nonce = EXCLUDED.nonce,
                        ciphertext = EXCLUDED.ciphertext,
                        updated_at = EXCLUDED.updated_at
                    RETURNING mailbox_id
                    """,
                    (record.version, record.wrapped_key, record.nonce,
                     record.ciphertext, _utc_now(), mailbox_id, user_id),
                )
                if cursor.fetchone() is None:
                    raise TenantAccessDenied("mailbox not found")

    def load_credentials(self, user_id, mailbox_id):
        with self.database.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.version, c.wrapped_key, c.nonce, c.ciphertext
                FROM oauth_credentials AS c
                JOIN mailboxes AS m ON m.id = c.mailbox_id
                WHERE m.id = %s AND m.user_id = %s
                  AND m.disconnected_at IS NULL
                """,
                (mailbox_id, user_id),
            )
            row = cursor.fetchone()
        if row is None:
            raise TenantAccessDenied("mailbox credential not found")
        return EncryptedMailboxToken(*row)

    def mailbox_for_user(self, user_id, mailbox_id):
        with self.database.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, google_subject, address, disconnected_at
                FROM mailboxes
                WHERE id = %s AND user_id = %s AND disconnected_at IS NULL
                """,
                (mailbox_id, user_id),
            )
            row = cursor.fetchone()
        if row is None:
            raise TenantAccessDenied("mailbox not found")
        return Mailbox(*row)

    def mailboxes_for_user(self, user_id):
        with self.database.cursor() as cursor:
            cursor.execute(
                """
                SELECT m.id, m.address, s.timezone, s.run_at, s.enabled,
                       s.next_run_at, latest.status, COALESCE(latest.processed_count, 0),
                       latest.requested_count
                FROM mailboxes AS m
                JOIN mailbox_settings AS s ON s.mailbox_id = m.id
                LEFT JOIN LATERAL (
                    SELECT status, processed_count, requested_count
                    FROM jobs WHERE mailbox_id = m.id
                    ORDER BY created_at DESC LIMIT 1
                ) AS latest ON true
                WHERE m.user_id = %s AND m.disconnected_at IS NULL
                ORDER BY lower(m.address)
                """,
                (user_id,),
            )
            return [MailboxView(*row) for row in cursor.fetchall()]

    def disconnect_mailbox(self, user_id, mailbox_id, *, now=None):
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE mailboxes SET disconnected_at = %s
                    WHERE id = %s AND user_id = %s AND disconnected_at IS NULL
                    RETURNING id
                    """,
                    (now or _utc_now(), mailbox_id, user_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise TenantAccessDenied("mailbox not found")
                cursor.execute(
                    "DELETE FROM oauth_credentials WHERE mailbox_id = %s",
                    (mailbox_id,),
                )
        return True

    def enqueue_job(self, user_id, mailbox_id, kind, idempotency_key,
                    *, requested_count=None, run_after=None):
        if kind not in ALLOWED_JOB_KINDS:
            raise TenantStoreError("unsupported job kind")
        if requested_count is not None and not 1 <= requested_count <= 5000:
            raise TenantStoreError("requested count must be between 1 and 5000")
        job_id = uuid.uuid4()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO jobs
                        (id, mailbox_id, kind, idempotency_key,
                         requested_count, run_after)
                    SELECT %s, m.id, %s, %s, %s, %s
                    FROM mailboxes AS m
                    WHERE m.id = %s AND m.user_id = %s
                      AND m.disconnected_at IS NULL
                    ON CONFLICT (mailbox_id, idempotency_key) DO UPDATE
                    SET idempotency_key = EXCLUDED.idempotency_key
                    RETURNING id
                    """,
                    (job_id, kind, str(idempotency_key), requested_count,
                     run_after or _utc_now(), mailbox_id, user_id),
                )
                row = cursor.fetchone()
        if row is None:
            raise TenantAccessDenied("mailbox not found")
        return row[0]

    def enqueue_due_jobs(self, *, now=None, limit=100):
        """Move due schedules into the queue without double-enqueueing."""
        now = now or _utc_now()
        if not 1 <= int(limit) <= 1000:
            raise TenantStoreError("scheduler batch size is invalid")
        enqueued = []
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT s.mailbox_id, s.timezone, s.run_at, s.next_run_at,
                           s.max_scan
                    FROM mailbox_settings AS s
                    JOIN mailboxes AS m ON m.id = s.mailbox_id
                    WHERE s.enabled = true AND s.next_run_at <= %s
                      AND m.disconnected_at IS NULL
                    ORDER BY s.next_run_at
                    FOR UPDATE OF s SKIP LOCKED
                    LIMIT %s
                    """,
                    (now, int(limit)),
                )
                due = cursor.fetchall()
                for mailbox_id, timezone_name, run_at, scheduled_at, max_scan in due:
                    job_id = uuid.uuid4()
                    request_key = f"daily:{scheduled_at.isoformat()}"
                    cursor.execute(
                        """
                        INSERT INTO jobs
                            (id, mailbox_id, kind, idempotency_key,
                             requested_count, run_after)
                        VALUES (%s, %s, 'daily', %s, %s, %s)
                        ON CONFLICT (mailbox_id, idempotency_key) DO NOTHING
                        RETURNING id
                        """,
                        (job_id, mailbox_id, request_key, max_scan, now),
                    )
                    inserted = cursor.fetchone()
                    if inserted is not None:
                        enqueued.append(inserted[0])
                    next_run = next_scheduled_run(
                        timezone_name, run_at, max(now, scheduled_at)
                    )
                    cursor.execute(
                        """
                        UPDATE mailbox_settings SET next_run_at = %s,
                            updated_at = %s WHERE mailbox_id = %s
                        """,
                        (next_run, now, mailbox_id),
                    )
        return enqueued

    def claim_next_job(self, worker_id, *, now=None,
                       lease=dt.timedelta(minutes=10)):
        """Claim one due job while locking its mailbox row.

        Locking both the job and mailbox makes concurrent workers skip every
        other queued operation for that mailbox. Different mailbox rows remain
        available, so independent accounts can run concurrently.
        """
        now = now or _utc_now()
        attempt_id = uuid.uuid4()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    WITH candidate AS (
                        SELECT j.id
                        FROM jobs AS j
                        JOIN mailboxes AS m ON m.id = j.mailbox_id
                        WHERE j.status = 'queued'
                          AND j.run_after <= %s
                          AND m.disconnected_at IS NULL
                          AND NOT EXISTS (
                              SELECT 1 FROM jobs AS active
                              WHERE active.mailbox_id = j.mailbox_id
                                AND active.status = 'running'
                          )
                        ORDER BY j.run_after, j.created_at
                        FOR UPDATE OF j, m SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE jobs AS j
                    SET status = 'running', started_at = COALESCE(started_at, %s),
                        leased_until = %s, worker_id = %s
                    FROM candidate AS c
                    WHERE j.id = c.id
                    RETURNING j.id, j.mailbox_id, j.kind, j.requested_count,
                              j.processed_count, j.group_size
                    """,
                    (now, now, now + lease, str(worker_id)),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                cursor.execute(
                    """
                    INSERT INTO job_attempts
                        (id, job_id, attempt_number, started_at)
                    SELECT %s, %s, COALESCE(MAX(attempt_number), 0) + 1, %s
                    FROM job_attempts WHERE job_id = %s
                    RETURNING attempt_number
                    """,
                    (attempt_id, row[0], now, row[0]),
                )
                attempt_number = cursor.fetchone()[0]
        return ClaimedJob(*row, attempt_number)

    def update_job_progress(self, job_id, worker_id, processed_count,
                            *, now=None, lease=dt.timedelta(minutes=10)):
        if int(processed_count) < 0:
            raise TenantStoreError("processed count cannot be negative")
        now = now or _utc_now()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE jobs SET processed_count = %s, leased_until = %s
                    WHERE id = %s AND worker_id = %s AND status = 'running'
                      AND processed_count <= %s
                    RETURNING id
                    """,
                    (int(processed_count), now + lease, job_id,
                     str(worker_id), int(processed_count)),
                )
                if cursor.fetchone() is None:
                    raise TenantAccessDenied("job lease is not owned")

    def finish_job(self, job_id, worker_id, *, succeeded, error_code=None,
                   now=None):
        now = now or _utc_now()
        outcome = "succeeded" if succeeded else "failed"
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE jobs SET status = %s, finished_at = %s,
                        leased_until = NULL, last_error_code = %s
                    WHERE id = %s AND worker_id = %s AND status = 'running'
                    RETURNING id
                    """,
                    (outcome, now, str(error_code or "") or None,
                     job_id, str(worker_id)),
                )
                if cursor.fetchone() is None:
                    raise TenantAccessDenied("job lease is not owned")
                cursor.execute(
                    """
                    UPDATE job_attempts SET finished_at = %s, outcome = %s,
                        error_code = %s
                    WHERE job_id = %s AND finished_at IS NULL
                    """,
                    (now, outcome, str(error_code or "") or None, job_id),
                )

    def requeue_expired_jobs(self, *, now=None):
        now = now or _utc_now()
        with self.database.transaction():
            with self.database.cursor() as cursor:
                cursor.execute(
                    """
                    WITH expired AS (
                        UPDATE jobs SET status = 'queued', worker_id = NULL,
                            leased_until = NULL, run_after = %s,
                            last_error_code = 'lease_expired'
                        WHERE status = 'running' AND leased_until < %s
                        RETURNING id
                    )
                    UPDATE job_attempts AS a
                    SET finished_at = %s, outcome = 'retry',
                        error_code = 'lease_expired'
                    FROM expired AS e
                    WHERE a.job_id = e.id AND a.finished_at IS NULL
                    RETURNING a.job_id
                    """,
                    (now, now, now),
                )
                return [row[0] for row in cursor.fetchall()]

    def message_processed(self, mailbox_id, gmail_message_id, policy_version):
        with self.database.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM message_state
                WHERE mailbox_id = %s AND gmail_message_id = %s
                  AND policy_version = %s
                """,
                (mailbox_id, str(gmail_message_id), int(policy_version)),
            )
            return cursor.fetchone() is not None
