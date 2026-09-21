DO $$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'PostgreSQL 15 or newer is required';
    END IF;
END;
$$;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    identity_issuer text NOT NULL,
    identity_subject text NOT NULL,
    display_email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    UNIQUE (identity_issuer, identity_subject),
    CHECK (length(identity_issuer) BETWEEN 1 AND 500),
    CHECK (length(identity_subject) BETWEEN 1 AND 500),
    CHECK (length(display_email) BETWEEN 3 AND 320)
);

CREATE UNIQUE INDEX users_display_email_unique
    ON users (lower(display_email));

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    csrf_secret bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK (octet_length(token_hash) = 32),
    CHECK (octet_length(csrf_secret) = 32),
    CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expiry_idx ON sessions(expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE mailboxes (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    google_subject text NOT NULL,
    address text NOT NULL,
    connected_at timestamptz NOT NULL DEFAULT now(),
    last_authorized_at timestamptz NOT NULL DEFAULT now(),
    disconnected_at timestamptz,
    UNIQUE (google_subject),
    UNIQUE (id, user_id),
    CHECK (length(google_subject) BETWEEN 1 AND 500),
    CHECK (length(address) BETWEEN 3 AND 320)
);

CREATE UNIQUE INDEX mailboxes_active_address_unique
    ON mailboxes (lower(address)) WHERE disconnected_at IS NULL;
CREATE INDEX mailboxes_user_id_idx ON mailboxes(user_id);

CREATE TABLE oauth_credentials (
    mailbox_id uuid PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    version integer NOT NULL DEFAULT 1 CHECK (version = 1),
    wrapped_key bytea NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mailbox_settings (
    mailbox_id uuid PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    timezone text NOT NULL DEFAULT 'UTC',
    run_at time NOT NULL DEFAULT TIME '18:00',
    enabled boolean NOT NULL DEFAULT true,
    max_scan integer NOT NULL DEFAULT 25 CHECK (max_scan BETWEEN 0 AND 5000),
    write_limit integer NOT NULL DEFAULT 125 CHECK (write_limit BETWEEN 0 AND 5000),
    max_drafts integer NOT NULL DEFAULT 25 CHECK (max_drafts BETWEEN 0 AND 5000),
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    next_run_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX mailbox_settings_due_idx
    ON mailbox_settings(next_run_at)
    WHERE enabled = true AND next_run_at IS NOT NULL;

CREATE TABLE jobs (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('incoming', 'daily', 'backfill', 'undo')),
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    idempotency_key text NOT NULL,
    requested_count integer CHECK (requested_count BETWEEN 1 AND 5000),
    processed_count integer NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    group_size integer NOT NULL DEFAULT 200 CHECK (group_size BETWEEN 1 AND 500),
    run_after timestamptz NOT NULL DEFAULT now(),
    leased_until timestamptz,
    worker_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    last_error_code text,
    UNIQUE (mailbox_id, idempotency_key),
    UNIQUE (id, mailbox_id)
);

CREATE INDEX jobs_claim_idx ON jobs(run_after, created_at)
    WHERE status = 'queued';
CREATE INDEX jobs_mailbox_history_idx ON jobs(mailbox_id, created_at DESC);

CREATE UNIQUE INDEX jobs_one_active_mailbox_operation
    ON jobs(mailbox_id) WHERE status = 'running';

CREATE TABLE job_attempts (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    outcome text CHECK (outcome IN ('succeeded', 'retry', 'failed')),
    error_code text,
    UNIQUE (job_id, attempt_number)
);

CREATE TABLE message_state (
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    gmail_message_id text NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version > 0),
    status text NOT NULL,
    label_id text,
    draft_id text,
    thread_id text,
    job_id uuid,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, gmail_message_id, policy_version),
    FOREIGN KEY (job_id, mailbox_id)
        REFERENCES jobs(id, mailbox_id) ON DELETE SET NULL (job_id)
);

CREATE TABLE rollback_entries (
    id uuid PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    job_id uuid NOT NULL,
    gmail_message_id text NOT NULL,
    action text NOT NULL CHECK (action IN ('draft_created', 'label_added')),
    target_id text NOT NULL,
    rolled_back_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (job_id, gmail_message_id, action, target_id),
    FOREIGN KEY (job_id, mailbox_id)
        REFERENCES jobs(id, mailbox_id) ON DELETE CASCADE
);

CREATE INDEX rollback_entries_mailbox_idx
    ON rollback_entries(mailbox_id, created_at DESC);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    mailbox_id uuid REFERENCES mailboxes(id) ON DELETE SET NULL,
    event_type text NOT NULL,
    outcome text NOT NULL,
    request_id uuid,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (mailbox_id IS NULL OR user_id IS NOT NULL),
    FOREIGN KEY (mailbox_id, user_id)
        REFERENCES mailboxes(id, user_id) ON DELETE SET NULL (mailbox_id)
);

CREATE INDEX audit_events_user_idx ON audit_events(user_id, created_at DESC);
CREATE INDEX audit_events_mailbox_idx
    ON audit_events(mailbox_id, created_at DESC);
