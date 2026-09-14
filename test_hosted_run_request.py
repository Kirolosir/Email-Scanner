import datetime as dt
import json
import stat

import pytest

import connection
import hosted_run_request as requests


UTC = dt.timezone.utc
NOW = dt.datetime(2026, 9, 9, 16, 0, tzinfo=UTC)
ACCOUNT = "owner@example.test"


def _ready_connection(root):
    occupant = connection.connect(root, ACCOUNT, now=NOW)
    occupant.directory.mkdir(parents=True, exist_ok=True)
    for name in requests.REQUIRED_SETUP_FILES:
        (occupant.directory / name).write_text("{}", encoding="utf-8")
    return occupant


def test_request_requires_a_connected_account_and_complete_setup(tmp_path):
    with pytest.raises(requests.RunRequestError, match="link"):
        requests.request_run(tmp_path, now=NOW)
    assert not (tmp_path / "active" / requests.REQUEST_FILE).exists()

    occupant = connection.connect(tmp_path, ACCOUNT, now=NOW)
    with pytest.raises(requests.RunRequestError, match="save labels"):
        requests.request_run(tmp_path, now=NOW)
    assert not requests.request_path(occupant.directory).exists()


def test_request_is_private_account_bound_and_consumed_once(tmp_path):
    occupant = _ready_connection(tmp_path)
    requested_epoch = requests.request_run(tmp_path, now=NOW)
    path = requests.request_path(occupant.directory)

    assert requested_epoch == int(NOW.timestamp())
    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document) == {
        "version", "account_hash", "requested_at", "scope", "message_count",
        "rollback_group",
    }
    assert document["scope"] == "recent"
    assert document["message_count"] is None
    assert document["rollback_group"] is None
    assert "@" not in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert requests.consume_request(occupant.directory, occupant, now=NOW)
    assert not path.exists()
    assert not requests.consume_request(occupant.directory, occupant, now=NOW)


def test_history_request_is_bounded_and_carries_only_the_count(tmp_path):
    occupant = _ready_connection(tmp_path)
    requests.request_run(tmp_path, now=NOW, history_count=75)

    document = requests.load_request(occupant.directory, occupant, now=NOW)
    assert document["scope"] == "history"
    assert document["message_count"] == 75
    for invalid in (0, requests.MAX_HISTORY_MESSAGES + 1, True, "50"):
        with pytest.raises(requests.RunRequestError, match="history count"):
            requests.request_run(tmp_path, now=NOW, history_count=invalid)


def test_repeat_click_is_refused_instead_of_queueing_a_duplicate(tmp_path):
    occupant = _ready_connection(tmp_path)
    requests.request_run(tmp_path, now=NOW)
    later = NOW + dt.timedelta(minutes=2)
    with pytest.raises(requests.RunAlreadyActive, match="already queued"):
        requests.request_run(tmp_path, now=later)

    document = json.loads(
        requests.request_path(occupant.directory).read_text(encoding="utf-8")
    )
    assert document["requested_at"] == NOW.isoformat(timespec="seconds")


def test_running_lifecycle_operation_is_reported_without_waiting(tmp_path):
    _ready_connection(tmp_path)
    with connection.lifecycle_lock(tmp_path):
        with pytest.raises(requests.RunAlreadyActive, match="in progress"):
            requests.request_run(tmp_path, now=NOW)


def test_altered_or_expired_requests_fail_closed(tmp_path):
    occupant = _ready_connection(tmp_path)
    requests.request_run(tmp_path, now=NOW)
    path = requests.request_path(occupant.directory)

    document = json.loads(path.read_text(encoding="utf-8"))
    document["account_hash"] = "0" * 16
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(requests.RunRequestError, match="another account"):
        requests.load_request(occupant.directory, occupant, now=NOW)

    requests.discard_request(occupant.directory)
    requests.request_run(tmp_path, now=NOW)
    with pytest.raises(requests.RunRequestError, match="expired"):
        requests.load_request(
            occupant.directory, occupant,
            now=NOW + requests.MAX_REQUEST_AGE + dt.timedelta(seconds=1),
        )


def test_disabled_connection_cannot_request_a_run(tmp_path):
    occupant = _ready_connection(tmp_path)
    connection.update_settings(tmp_path, ACCOUNT, enabled=False)

    with pytest.raises(requests.RunRequestError, match="not enabled"):
        requests.request_run(tmp_path, now=NOW)
    assert not requests.request_path(occupant.directory).exists()


def test_undo_request_requires_typed_confirmation_and_latest_group(tmp_path):
    occupant = _ready_connection(tmp_path)
    rollback = occupant.directory / "rollback"
    rollback.mkdir()
    (rollback / "1788969600-00000.json").write_text(json.dumps({
        "version": 1, "group_id": "1788969600",
        "created_at": NOW.isoformat(timespec="seconds"),
        "completed_at": NOW.isoformat(timespec="seconds"), "undone_at": None,
        "entries": [{
            "message_id": "m1", "draft_id": "d1", "labels": ["Triage/Other"],
            "draft_undone": False, "labels_undone": False,
        }],
    }), encoding="utf-8")

    with pytest.raises(requests.RunRequestError, match="type UNDO"):
        requests.request_undo(
            tmp_path, group_id="1788969600", confirmation="undo", now=NOW
        )
    requests.request_undo(
        tmp_path, group_id="1788969600", confirmation="UNDO", now=NOW
    )
    document = requests.load_request(occupant.directory, occupant, now=NOW)
    assert document["scope"] == "rollback"
    assert document["rollback_group"] == "1788969600"
