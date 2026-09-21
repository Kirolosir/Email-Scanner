ALTER TABLE mailbox_settings
    DROP CONSTRAINT mailbox_settings_write_limit_check;

ALTER TABLE mailbox_settings
    ADD CONSTRAINT mailbox_settings_write_limit_check
    CHECK (write_limit BETWEEN 0 AND 25000);
