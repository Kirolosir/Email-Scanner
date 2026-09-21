import datetime as dt
import json
import uuid

from tenant_settings import save_mailbox_settings
from tenant_store import Mailbox


NOW = dt.datetime(2026, 9, 21, 18, 0, tzinfo=dt.timezone.utc)


class Store:
    def __init__(self):
        self.user_id = uuid.uuid4()
        self.mailbox = Mailbox(
            uuid.uuid4(), self.user_id, "subject-1",
            "owner@example.test", None,
        )
        self.events = []

    def mailbox_for_user(self, user_id, mailbox_id):
        assert (user_id, mailbox_id) == (self.user_id, self.mailbox.id)
        return self.mailbox

    def begin_mailbox_setup(self, *args):
        self.events.append(("begin", args))

    def update_mailbox_settings(self, *args, **kwargs):
        self.events.append(("settings", args, kwargs))

    def set_mailbox_setup(self, *args, **kwargs):
        self.events.append(("status", args, kwargs))


def _form():
    return {
        "labels": "Scheduling | Scheduling\nFinance | Finance",
        "timezone": "America/New_York",
        "run_at": "18:30",
        "display_name": "Owner",
        "role": "Head Coach",
        "organization": "Example College",
        "signature": "Owner",
        "max_scan": "2000",
        "confirm_unsent_drafts": "yes",
    }


def test_settings_are_written_under_mailbox_uuid_and_activate_last(tmp_path):
    store = Store()
    save_mailbox_settings(
        store, tmp_path, store.user_id, store.mailbox.id, _form(), now=NOW
    )
    directory = tmp_path / "mailboxes" / str(store.mailbox.id)
    account = json.loads((directory / "account.json").read_text())
    assert account["account"] == "owner@example.test"
    assert account["draft_all_replyable_messages"] is True
    assert (directory / "taxonomy-confirmation.json").is_file()
    assert (directory / "ai-drafting-approval.json").is_file()
    assert (directory / "label-setup-pending.json").is_file()
    assert store.events[0][0] == "begin"
    assert store.events[-1] == (
        "status", (store.user_id, store.mailbox.id, "ready"), {}
    )
    settings = next(event for event in store.events if event[0] == "settings")
    assert settings[2]["max_scan"] == 2000
    assert settings[2]["max_drafts"] == 2000
    assert settings[2]["write_limit"] == 10000
