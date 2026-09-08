import datetime as dt
import json
from pathlib import Path

import pytest

import connection
import hosted_runner as runner


UTC = dt.timezone.utc
A = "owner@example.test"


def _environment(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    client = tmp_path / "credentials.json"
    client.write_text(json.dumps({"installed": {
        "client_id": "client-id",
        "client_secret": "client-secret",
        "token_uri": "https://oauth2.example.test/token",
    }}), encoding="utf-8")
    monkeypatch.setattr(runner, "verify_durable_state_root",
                        lambda *_a, **_k: True)
    return root, client, {
        "HOSTED_STATE_ROOT": str(root),
        "HOSTED_REQUIRE_MOUNTPOINT": "false",
        "CONNECTION_KMS_KEY": (
            "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        ),
        "GMAIL_CREDENTIALS_PATH": str(client),
    }


def test_vacant_runner_contacts_nothing(tmp_path, monkeypatch):
    _root, _client, env = _environment(tmp_path, monkeypatch)

    def explode(*_args, **_kwargs):
        raise AssertionError("a service was constructed")

    assert runner.run_if_due(env, service_builder=explode) == 0


def test_incomplete_setup_is_recorded_before_token_or_gmail(tmp_path,
                                                             monkeypatch):
    root, _client, env = _environment(tmp_path, monkeypatch)
    seat = connection.connect(root, A, timezone="UTC", run_at="18:00")
    monkeypatch.setattr(runner, "build_provider",
                        lambda *_a, **_k: pytest.fail("KMS reached"))

    code = runner.run_if_due(
        env, now=dt.datetime(2026, 9, 8, 18, 1, tzinfo=UTC),
        service_builder=lambda *_a, **_k: pytest.fail("Gmail reached"),
    )

    assert code == 2
    status = json.loads((seat.directory / "daily-status.json").read_text())
    assert status["last_run"]["safe_error_codes"] == [
        "account_setup_incomplete"
    ]


def test_not_due_never_decrypts_or_contacts_gmail(tmp_path, monkeypatch):
    root, _client, env = _environment(tmp_path, monkeypatch)
    seat = connection.connect(root, A, timezone="UTC", run_at="18:00")
    for name in (runner.CONFIG_FILE, runner.TAXONOMY_APPROVAL_FILE,
                 runner.AI_APPROVAL_FILE):
        (seat.directory / name).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(runner, "build_provider",
                        lambda *_a, **_k: pytest.fail("KMS reached"))

    assert runner.run_if_due(
        env, now=dt.datetime(2026, 9, 8, 17, 0, tzinfo=UTC),
        service_builder=lambda *_a, **_k: pytest.fail("Gmail reached"),
    ) == 0


def test_credentials_merge_refresh_token_with_separate_client(tmp_path):
    client = tmp_path / "credentials.json"
    client.write_text(json.dumps({"installed": {
        "client_id": "client-id",
        "client_secret": "client-secret",
        "token_uri": "https://oauth2.example.test/token",
    }}), encoding="utf-8")
    credentials = runner.hosted_credentials(
        {"refresh_token": "refresh-value"}, client
    )
    assert credentials.refresh_token == "refresh-value"
    assert credentials.client_id == "client-id"
    assert credentials.client_secret == "client-secret"


def test_due_runner_injects_gmail_service_and_all_safety_limits(
        tmp_path, monkeypatch):
    root, _client, env = _environment(tmp_path, monkeypatch)
    seat = connection.connect(root, A, timezone="UTC", run_at="18:00")
    for name in (runner.CONFIG_FILE, runner.TAXONOMY_APPROVAL_FILE,
                 runner.AI_APPROVAL_FILE):
        (seat.directory / name).write_text("{}", encoding="utf-8")

    marker_provider = object()
    marker_service = object()
    monkeypatch.setattr(runner, "build_provider",
                        lambda _key: marker_provider)
    monkeypatch.setattr(
        runner.connection_tokens, "load_token",
        lambda actual, provider: (
            {"refresh_token": "refresh-value"}
            if actual.account == A and provider is marker_provider
            else pytest.fail("wrong token lookup")
        ),
    )
    built = []

    def service_builder(api, version, *, credentials):
        built.append((api, version, credentials.refresh_token))
        return marker_service

    calls = []

    def daily_main(argv, *, gmail_service=None):
        calls.append((argv, gmail_service))
        return 0

    monkeypatch.setattr(runner.daily_triage, "main", daily_main)

    code = runner.run_if_due(
        env, now=dt.datetime(2026, 9, 8, 18, 1, tzinfo=UTC),
        service_builder=service_builder,
    )

    assert code == 0
    assert built == [("gmail", "v1", "refresh-value")]
    assert len(calls) == 1 and calls[0][1] is marker_service
    argv = calls[0][0]
    assert all(flag in argv for flag in (
        "--scheduled", "--apply", "--yes",
        "--max-scan", "--limit", "--max-drafts",
    ))
    assert argv[argv.index("--max-scan") + 1] == str(seat.max_scan)
    assert argv[argv.index("--limit") + 1] == str(seat.limit)
    assert argv[argv.index("--max-drafts") + 1] == str(seat.max_drafts)


def test_the_timer_checks_often_but_the_runner_owns_due_decisions():
    timer = Path("hosted-triage.timer.example").read_text(encoding="utf-8")
    assert "OnCalendar=*:0/15" in timer
    assert "Persistent=true" in timer


def test_the_runner_service_is_sandboxed_to_the_state_disk():
    unit = Path("hosted-triage.service.example").read_text(encoding="utf-8")
    assert "User=email-scanner" in unit
    assert "RequiresMountsFor=/mnt/state" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/mnt/state" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "hosted_runner.py" in unit


def test_no_plaintext_token_file_api_exists_in_the_runner():
    source = Path("hosted_runner.py").read_text(encoding="utf-8")
    assert "NamedTemporaryFile" not in source
    assert "mkstemp" not in source
    assert "_write_token" not in source
    assert "token.json" not in source
