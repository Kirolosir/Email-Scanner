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
    requests.request_run(tmp_path, now=NOW)
    path = requests.request_path(occupant.directory)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document) == {"version", "account_hash", "requested_at"}
    assert "@" not in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert requests.consume_request(occupant.directory, occupant, now=NOW)
    assert not path.exists()
    assert not requests.consume_request(occupant.directory, occupant, now=NOW)


def test_repeat_clicks_coalesce_into_one_fresh_request(tmp_path):
    occupant = _ready_connection(tmp_path)
    requests.request_run(tmp_path, now=NOW)
    later = NOW + dt.timedelta(minutes=2)
    requests.request_run(tmp_path, now=later)

    document = json.loads(
        requests.request_path(occupant.directory).read_text(encoding="utf-8")
    )
    assert document["requested_at"] == later.isoformat(timespec="seconds")


def test_altered_or_expired_requests_fail_closed(tmp_path):
    occupant = _ready_connection(tmp_path)
    requests.request_run(tmp_path, now=NOW)
    path = requests.request_path(occupant.directory)

    document = json.loads(path.read_text(encoding="utf-8"))
    document["account_hash"] = "0" * 16
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(requests.RunRequestError, match="another account"):
        requests.load_request(occupant.directory, occupant, now=NOW)

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
