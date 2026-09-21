import datetime as dt
import json
import uuid

import connection
import connection_tokens
from connection_tokens import FileKeyProvider
from legacy_tenant_import import import_legacy_account
from tenant_store import Mailbox, UserIdentity


NOW = dt.datetime(2026, 9, 21, 18, 0, tzinfo=dt.timezone.utc)


class Store:
    def __init__(self, account):
        self.user = UserIdentity(
            uuid.uuid4(), "https://accounts.google.com", "subject-1", account
        )
        self.mailbox_id = uuid.uuid4()
        self.connected = []
        self.settings = []
        self.setup = []

    def user_for_email(self, account):
        assert account == self.user.display_email
        return self.user

    def connect_mailbox(self, *args, **kwargs):
        self.connected.append((args, kwargs))
        return Mailbox(
            self.mailbox_id, self.user.id, self.user.identity_subject,
            self.user.display_email, None,
        )

    def update_mailbox_settings(self, *args, **kwargs):
        self.settings.append((args, kwargs))

    def set_mailbox_setup(self, *args, **kwargs):
        self.setup.append((args, kwargs))


def test_import_copies_private_artifacts_and_leaves_legacy_state(tmp_path):
    account = "owner@example.test"
    legacy = connection.connect(
        tmp_path, account, timezone="America/New_York", run_at="18:30",
        now=NOW, limits={"max_scan": 50, "limit": 40, "max_drafts": 30},
    )
    provider = FileKeyProvider(tmp_path / "key").create()
    connection_tokens.store_token(
        legacy, {"refresh_token": "private-refresh"}, provider
    )
    for name in (
        "account.json", "taxonomy-confirmation.json",
        "ai-drafting-approval.json", "daily-state.json",
    ):
        (legacy.directory / name).write_text(json.dumps({"name": name}))
    (legacy.directory / "templates").mkdir()
    (legacy.directory / "templates" / "reply.txt").write_text("Hello")

    store = Store(account)
    imported = import_legacy_account(
        tmp_path, store, provider, now=NOW
    )

    target = tmp_path / "mailboxes" / str(imported.id)
    assert (target / "account.json").is_file()
    assert (target / "templates" / "reply.txt").read_text() == "Hello"
    assert not (target / "token.enc.json").exists()
    assert connection.current(tmp_path).account == account
    assert connection_tokens.load_token(legacy, provider) == {
        "refresh_token": "private-refresh"
    }
    token_document = store.connected[0][0][3]
    assert token_document == {"refresh_token": "private-refresh"}
    assert store.settings[0][1]["timezone"] == "America/New_York"
    assert store.settings[0][1]["run_at"] == dt.time(18, 30)
    assert store.setup[-1] == ((store.user.id, imported.id, "ready"), {})
