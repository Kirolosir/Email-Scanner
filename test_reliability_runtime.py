import datetime as dt
import json
import os

from connection_tokens import FileKeyProvider
from encrypted_backup import create_verified_backup, restore_backup
from retry_queue import RetryQueue


UTC = dt.timezone.utc


def test_retry_queue_defers_then_releases_and_clears(tmp_path):
    path = tmp_path / "private" / "retry-queue.json"
    now = dt.datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    queue = RetryQueue(path)
    queue.update(["message-1"], now=now)
    assert queue.due(now, 10) == []
    assert queue.due(now + dt.timedelta(minutes=6), 10) == ["message-1"]
    queue.update(completed_ids=["message-1"], now=now)
    assert len(RetryQueue(path)) == 0
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_encrypted_backup_round_trip_and_restore(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    (active / "account.json").write_text(
        json.dumps({"timezone": "UTC"}), encoding="utf-8"
    )
    review = active / "review"
    review.mkdir()
    (review / "daily.json").write_text(
        json.dumps({"counts": {"drafted": 2}}), encoding="utf-8"
    )
    rollback = active / "rollback"
    rollback.mkdir()
    (rollback / "1788969600-00000.json").write_text(
        json.dumps({"safe": "rollback"}), encoding="utf-8"
    )
    provider = FileKeyProvider(tmp_path / "key").create()
    backup = create_verified_backup(
        active, tmp_path / "backups", "seat-1", provider,
        now=dt.datetime(2026, 9, 13, tzinfo=UTC),
    )
    encrypted_text = backup.read_text(encoding="utf-8")
    assert "timezone" not in encrypted_text
    restored = restore_backup(
        backup, tmp_path / "restored", "seat-1", provider
    )
    assert json.loads((restored / "account.json").read_text())["timezone"] == "UTC"
    assert json.loads((restored / "review" / "daily.json").read_text())[
        "counts"
    ]["drafted"] == 2
    assert json.loads(
        (restored / "rollback" / "1788969600-00000.json").read_text()
    ) == {"safe": "rollback"}
