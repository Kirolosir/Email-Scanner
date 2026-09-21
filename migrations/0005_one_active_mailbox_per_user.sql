CREATE UNIQUE INDEX mailboxes_one_active_per_user
    ON mailboxes(user_id) WHERE disconnected_at IS NULL;
