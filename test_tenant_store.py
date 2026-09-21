import datetime as dt
import re
import uuid
from pathlib import Path

import pytest

from connection_tokens import FileKeyProvider, TokenStoreError
from db_migrate import discover_migrations
from mailbox_tokens import open_mailbox_token, seal_mailbox_token
from tenant_store import (
    SessionIdentity,
    TenantAccessDenied,
    TenantStoreError,
    csrf_value,
    next_scheduled_run,
    session_token_hash,
)


def test_session_bearers_are_strong_and_only_the_hash_is_persistable():
    token = "ab" * 32
    digest = session_token_hash(token)
    assert len(digest) == 32
    assert token.encode("ascii") not in digest
    assert digest == session_token_hash(token)


@pytest.mark.parametrize("token", ["", "short", "zz" * 32, "ab" * 31])
def test_malformed_session_bearers_fail_closed(token):
    with pytest.raises(TenantAccessDenied, match="invalid session"):
        session_token_hash(token)


def test_csrf_tokens_are_unique_to_each_session():
    user_id = uuid.uuid4()
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    first = SessionIdentity(uuid.uuid4(), user_id, "one@example.test", b"a" * 32, expires)
    second = SessionIdentity(uuid.uuid4(), user_id, "one@example.test", b"b" * 32, expires)
    assert csrf_value(first) != csrf_value(second)


def test_mailbox_uuid_is_authenticated_at_both_encryption_layers(tmp_path):
    provider = FileKeyProvider(tmp_path / "key").create()
    first = uuid.uuid4()
    second = uuid.uuid4()
    record = seal_mailbox_token(first, {"refresh_token": "private"}, provider)
    assert open_mailbox_token(first, record, provider) == {
        "refresh_token": "private"
    }
    with pytest.raises(TokenStoreError):
        open_mailbox_token(second, record, provider)


def test_schema_has_tenant_foreign_keys_and_idempotency_guards():
    schema = Path("migrations/0001_multitenant.sql").read_text(encoding="utf-8")
    required_tables = {
        "users", "sessions", "mailboxes", "oauth_credentials",
        "mailbox_settings", "jobs", "job_attempts", "message_state",
        "rollback_entries", "audit_events",
    }
    assert required_tables <= set(re.findall(r"CREATE TABLE (\w+)", schema))
    assert "PRIMARY KEY (mailbox_id, gmail_message_id, policy_version)" in schema
    assert "UNIQUE (mailbox_id, idempotency_key)" in schema
    assert "jobs_one_active_mailbox_operation" in schema
    assert schema.count("REFERENCES jobs(id, mailbox_id)") == 2
    assert "REFERENCES mailboxes(id, user_id)" in schema
    assert "FOR UPDATE OF j, m SKIP LOCKED" in Path("tenant_store.py").read_text(
        encoding="utf-8"
    )
    assert "ON DELETE CASCADE" in schema


def test_schema_never_uses_an_address_as_a_primary_key():
    schema = Path("migrations/0001_multitenant.sql").read_text(encoding="utf-8")
    assert not re.search(r"address\s+text\s+PRIMARY KEY", schema, re.IGNORECASE)
    assert "id uuid PRIMARY KEY" in schema


def test_migrations_are_ordered_and_have_stable_checksums():
    migrations = discover_migrations("migrations")
    assert [item[0] for item in migrations] == [
        "0001_multitenant.sql", "0002_mailbox_setup_state.sql",
    ]
    assert len(migrations[0][1]) == 32
    assert "CREATE TABLE users" in migrations[0][2]


def test_next_scheduled_run_preserves_local_time_across_dst():
    before = dt.datetime(2026, 3, 7, 22, 59, tzinfo=dt.timezone.utc)
    first = next_scheduled_run(
        "America/New_York", dt.time(18, 0), before
    )
    second = next_scheduled_run(
        "America/New_York", dt.time(18, 0), first
    )
    assert first.astimezone(dt.timezone.utc).hour == 23
    assert second.astimezone(dt.timezone.utc).hour == 22
    assert first.astimezone(dt.timezone(dt.timedelta(hours=-5))).hour == 18


def test_scheduler_refuses_naive_time():
    with pytest.raises(TenantStoreError, match="include a timezone"):
        next_scheduled_run("UTC", dt.time(18, 0), dt.datetime(2026, 1, 1))
