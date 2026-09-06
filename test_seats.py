"""Offline tests for the fixed seat roster and encrypted token storage."""
import ast
import json
import os
import stat
from pathlib import Path

import pytest

import seat_tokens
import seats
from seat_tokens import FileKeyProvider, TokenStoreError
from seats import MAX_SEATS, SeatConfigError, load_roster


def _seat(seat_id="coach", account=None, **overrides):
    document = {
        "id": seat_id,
        "account": account or f"{seat_id}@example.test",
        "timezone": "America/New_York",
        "run_at": "18:00",
        "directory": f"seats/{seat_id}",
        "account_config": f"seats/{seat_id}/account.json",
    }
    document.update(overrides)
    return document


def _roster(tmp_path, *documents, version=1):
    path = tmp_path / "roster.json"
    path.write_text(
        json.dumps({"version": version, "seats": list(documents)}),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------
# The cap is the tenancy model
# ---------------------------------------------------------------------

def test_three_seats_load(tmp_path):
    roster = load_roster(_roster(
        tmp_path, _seat("operator"), _seat("coach"), _seat("third")))
    assert [s.id for s in roster] == ["operator", "coach", "third"]
    assert len(roster) == MAX_SEATS


def test_a_fourth_seat_is_refused_with_an_explicit_reason(tmp_path):
    path = _roster(tmp_path, _seat("a"), _seat("b"), _seat("c"), _seat("d"))
    with pytest.raises(SeatConfigError, match="capped at 3"):
        load_roster(path)


def test_the_cap_is_a_reviewed_constant_not_a_default():
    """A deployment cannot grow the roster by editing only its config."""
    tree = ast.parse(Path("seats.py").read_text(encoding="utf-8"))
    assignments = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(getattr(t, "id", None) == "MAX_SEATS" for t in node.targets)
    ]
    assert len(assignments) == 1
    assert isinstance(assignments[0].value, ast.Constant), (
        "MAX_SEATS is computed rather than declared; the cap must be a "
        "literal a reviewer can see"
    )
    assert assignments[0].value.value == 3
    # It must also not be reachable from the environment or a config file.
    source = Path("seats.py").read_text(encoding="utf-8")
    assert "environ" not in source, "seats.py reads the environment"


# ---------------------------------------------------------------------
# Fail closed, fail whole
# ---------------------------------------------------------------------

def test_one_bad_seat_loads_no_seats(tmp_path):
    path = _roster(tmp_path, _seat("good"), _seat("BAD ID"))
    with pytest.raises(SeatConfigError, match="invalid seat id"):
        load_roster(path)


def test_duplicate_seat_id_is_refused(tmp_path):
    with pytest.raises(SeatConfigError, match="duplicate seat id"):
        load_roster(_roster(tmp_path, _seat("coach"), _seat("coach")))


def test_one_mailbox_cannot_be_two_seats(tmp_path):
    """Two schedules on one inbox would give two journals disagreeing."""
    path = _roster(
        tmp_path,
        _seat("a", account="shared@example.test"),
        _seat("b", account="SHARED@example.test"),
    )
    with pytest.raises(SeatConfigError, match="more than one seat"):
        load_roster(path)


@pytest.mark.parametrize("run_at", ["25:00", "18:70", "6pm", "18", "", "1800"])
def test_invalid_run_at_is_refused(tmp_path, run_at):
    with pytest.raises(SeatConfigError, match="run_at"):
        load_roster(_roster(tmp_path, _seat("coach", run_at=run_at)))


def test_unknown_timezone_is_refused(tmp_path):
    with pytest.raises(SeatConfigError, match="unknown timezone"):
        load_roster(_roster(tmp_path, _seat("coach", timezone="Mars/Olympus")))


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../escape", "../out"])
def test_paths_cannot_escape_the_roster_root(tmp_path, bad):
    with pytest.raises(SeatConfigError):
        load_roster(_roster(tmp_path, _seat("coach", directory=bad)))


def test_unsupported_keys_are_refused(tmp_path):
    with pytest.raises(SeatConfigError, match="unsupported seat keys"):
        load_roster(_roster(tmp_path, _seat("coach", send_mail=True)))


def test_wrong_version_is_refused(tmp_path):
    with pytest.raises(SeatConfigError, match="version 1"):
        load_roster(_roster(tmp_path, _seat("coach"), version=2))


def test_malformed_roster_is_refused(tmp_path):
    path = tmp_path / "roster.json"
    path.write_text("{{{", encoding="utf-8")
    with pytest.raises(SeatConfigError, match="not valid JSON"):
        load_roster(path)


# ---------------------------------------------------------------------
# Derived layout and bounded runs
# ---------------------------------------------------------------------

def test_seat_paths_are_derived_under_its_own_directory(tmp_path):
    seat = load_roster(_roster(tmp_path, _seat("coach")))[0]
    assert seat.state_path.name == "daily-state.json"
    assert seat.status_path.parent == seat.directory
    assert seat.review_dir.parent == seat.directory
    assert seat.lock_dir.parent == seat.directory
    assert str(seat.directory).startswith(str(tmp_path.resolve()))


def test_unattended_limits_default_bounded(tmp_path):
    seat = load_roster(_roster(tmp_path, _seat("coach")))[0]
    assert (seat.max_scan, seat.limit, seat.max_drafts) == (25, 25, 5)


def test_negative_limits_are_refused(tmp_path):
    with pytest.raises(SeatConfigError, match="nonnegative"):
        load_roster(_roster(tmp_path, _seat("coach", max_drafts=-1)))


def test_disabled_seats_are_excluded(tmp_path):
    roster = load_roster(_roster(
        tmp_path, _seat("a"), _seat("b", enabled=False)))
    assert [s.id for s in seats.enabled_seats(roster)] == ["a"]


def test_run_at_splits_into_hour_and_minute(tmp_path):
    seat = load_roster(_roster(tmp_path, _seat("coach", run_at="06:05")))[0]
    assert (seat.hour, seat.minute) == (6, 5)


# ---------------------------------------------------------------------
# Token storage
# ---------------------------------------------------------------------

TOKEN = {"refresh_token": "SECRET-REFRESH-VALUE", "scope": "gmail.modify"}


def _prepared(tmp_path, seat_id="coach"):
    seat = load_roster(_roster(tmp_path, _seat(seat_id)))[0]
    seat.directory.mkdir(parents=True, exist_ok=True)
    provider = FileKeyProvider(tmp_path / "kek.bin").create()
    return seat, provider


def test_token_round_trips(tmp_path):
    seat, provider = _prepared(tmp_path)
    seat_tokens.store_token(seat, TOKEN, provider)
    assert seat_tokens.load_token(seat, provider) == TOKEN


def test_stored_record_contains_no_plaintext(tmp_path):
    seat, provider = _prepared(tmp_path)
    path = seat_tokens.store_token(seat, TOKEN, provider)
    raw = path.read_text(encoding="utf-8")
    assert "SECRET-REFRESH-VALUE" not in raw
    assert "refresh_token" not in raw


def test_record_and_key_are_owner_only(tmp_path):
    seat, provider = _prepared(tmp_path)
    path = seat_tokens.store_token(seat, TOKEN, provider)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(provider.path).st_mode) == 0o600


def test_a_record_cannot_be_moved_to_another_seat(tmp_path):
    """The seat id is bound into both AEAD layers as associated data."""
    seat_a, provider = _prepared(tmp_path, "coach")
    seat_tokens.store_token(seat_a, TOKEN, provider)

    path_b = tmp_path / "roster2.json"
    path_b.write_text(json.dumps({"version": 1, "seats": [_seat("intruder")]}),
                      encoding="utf-8")
    seat_b = load_roster(path_b)[0]
    seat_b.directory.mkdir(parents=True, exist_ok=True)
    # Copy coach's record verbatim into the other seat's directory.
    seat_tokens.token_path(seat_b).write_bytes(
        seat_tokens.token_path(seat_a).read_bytes())

    with pytest.raises(TokenStoreError, match="different seat"):
        seat_tokens.load_token(seat_b, provider)


def test_a_tampered_ciphertext_is_refused(tmp_path):
    seat, provider = _prepared(tmp_path)
    path = seat_tokens.store_token(seat, TOKEN, provider)
    record = json.loads(path.read_text(encoding="utf-8"))
    flipped = bytearray(seat_tokens._unb64(record["ciphertext"]))
    flipped[-1] ^= 0x01
    record["ciphertext"] = seat_tokens._b64(bytes(flipped))
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(TokenStoreError, match="authentication"):
        seat_tokens.load_token(seat, provider)


def test_a_different_key_cannot_decrypt(tmp_path):
    seat, provider = _prepared(tmp_path)
    seat_tokens.store_token(seat, TOKEN, provider)
    wrong = FileKeyProvider(tmp_path / "other.bin").create()
    with pytest.raises(TokenStoreError):
        seat_tokens.load_token(seat, wrong)


def test_missing_token_is_a_clean_error(tmp_path):
    seat, provider = _prepared(tmp_path)
    with pytest.raises(TokenStoreError, match="no stored token"):
        seat_tokens.load_token(seat, provider)


def test_key_creation_refuses_to_clobber(tmp_path):
    provider = FileKeyProvider(tmp_path / "kek.bin").create()
    with pytest.raises(FileExistsError):
        provider.create()


def test_forget_removes_the_record_and_reports(tmp_path):
    seat, provider = _prepared(tmp_path)
    seat_tokens.store_token(seat, TOKEN, provider)
    assert seat_tokens.forget_token(seat) is True
    assert seat_tokens.forget_token(seat) is False


def test_errors_never_carry_the_token_or_a_path(tmp_path):
    """Messages surface to logs and status files; they must stay opaque."""
    seat, provider = _prepared(tmp_path)
    seat_tokens.store_token(seat, TOKEN, provider)
    wrong = FileKeyProvider(tmp_path / "other.bin").create()
    try:
        seat_tokens.load_token(seat, wrong)
    except TokenStoreError as exc:
        text = str(exc)
        assert "SECRET-REFRESH-VALUE" not in text
        assert str(tmp_path) not in text
    else:
        pytest.fail("expected a TokenStoreError")


# ---------------------------------------------------------------------
# Module boundaries
# ---------------------------------------------------------------------

def test_neither_module_contacts_the_network_or_runs_a_job():
    """seats.py resolves config; seat_tokens.py does crypto. Neither acts."""
    for name in ("seats.py", "seat_tokens.py"):
        tree = ast.parse(Path(name).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("gmail_auth", "gemini_client", "googleapiclient",
                          "urllib", "requests", "socket", "subprocess",
                          "daily_triage", "triage"):
            assert forbidden not in imported, (
                f"{name} imports {forbidden}"
            )


def test_revocation_is_documented_as_not_local_deletion():
    """A caller must not mistake forget_token for revoking the grant."""
    source = Path("seat_tokens.py").read_text(encoding="utf-8")
    assert "Local deletion is NOT revocation" in source
