CREATE TABLE oauth_transactions (
    state_hash bytea PRIMARY KEY,
    purpose text NOT NULL CHECK (purpose IN ('login', 'mailbox')),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    code_verifier text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CHECK ((purpose = 'login' AND user_id IS NULL)
        OR (purpose = 'mailbox' AND user_id IS NOT NULL)),
    CHECK (length(code_verifier) BETWEEN 20 AND 512),
    CHECK (expires_at > created_at)
);

CREATE INDEX oauth_transactions_expiry_idx
    ON oauth_transactions(expires_at);
