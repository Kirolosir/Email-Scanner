ALTER TABLE mailboxes
    ADD COLUMN setup_status text NOT NULL DEFAULT 'pending'
        CHECK (setup_status IN ('pending', 'ready', 'error')),
    ADD COLUMN setup_error_code text,
    ADD COLUMN artifact_version integer NOT NULL DEFAULT 1
        CHECK (artifact_version > 0);

CREATE INDEX mailboxes_ready_user_idx ON mailboxes(user_id, id)
    WHERE disconnected_at IS NULL AND setup_status = 'ready';
