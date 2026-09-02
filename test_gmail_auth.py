"""Offline tests for separate-account OAuth token handling."""
from types import SimpleNamespace

import pytest

import gmail_auth


class _FakeCredentials:
    valid = True

    def to_json(self):
        return "synthetic-token-for-offline-test"


class _FakeFlow:
    def __init__(self):
        self.options = None

    def run_local_server(self, **options):
        self.options = options
        return _FakeCredentials()


def test_new_account_forces_selection_and_can_verify_before_save(
        monkeypatch, tmp_path):
    credentials_path = tmp_path / "credentials.json"
    credentials_path.write_text("synthetic")
    token_path = tmp_path / "tokens" / "coach.json"
    flow = _FakeFlow()
    monkeypatch.setattr(
        gmail_auth.InstalledAppFlow,
        "from_client_secrets_file",
        lambda path, scopes: flow,
    )

    creds = gmail_auth.get_credentials(
        credentials_path, token_path, force_authorize=True,
        login_hint="coach@example.test", persist=False,
    )

    assert isinstance(creds, _FakeCredentials)
    assert flow.options["prompt"] == "select_account consent"
    assert flow.options["access_type"] == "offline"
    assert flow.options["login_hint"] == "coach@example.test"
    assert not token_path.exists(), "verification must happen before persistence"

    gmail_auth._write_token(creds, token_path)
    assert token_path.read_text() == "synthetic-token-for-offline-test"
    assert (token_path.stat().st_mode & 0o777) == 0o600
    assert (token_path.parent.stat().st_mode & 0o777) == 0o700


# --------------------------------------------------------------------
# A pipeline command must never open Google's sign-in flow.
#
# Found live: the scheduled job pins --token-path so an unattended run
# cannot touch the wrong mailbox. Pointed at a path that did not exist,
# get_credentials fell through to run_local_server(), minted a NEW
# credential for whichever account the machine's browser session held,
# and persisted it at that path. The pinning guarantee inverted: instead
# of refusing, it manufactured the very credential it was meant to
# constrain. An unattended run must fail closed.
# --------------------------------------------------------------------

class _ExplodingFlow:
    """Any use of this is a test failure: OAuth must not start."""

    @staticmethod
    def from_client_secrets_file(path, scopes):
        raise AssertionError(
            "interactive OAuth was started by a non-authorize caller"
        )


def test_missing_token_refuses_instead_of_authorizing(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_auth, "InstalledAppFlow", _ExplodingFlow)
    credentials_path = tmp_path / "credentials.json"
    credentials_path.write_text("synthetic")
    missing = tmp_path / "tokens" / "nonexistent.json"

    with pytest.raises(gmail_auth.TokenUnavailableError) as caught:
        gmail_auth.get_credentials(credentials_path, missing)

    assert "gmail_auth.py --authorize" in str(caught.value)
    assert not missing.exists(), "refusing must not leave a credential behind"


def test_get_gmail_service_never_authorizes(monkeypatch, tmp_path):
    """The pipeline entry point, which the 6 PM job reaches."""
    monkeypatch.setattr(gmail_auth, "InstalledAppFlow", _ExplodingFlow)
    missing = tmp_path / "tokens" / "nonexistent.json"

    with pytest.raises(gmail_auth.TokenUnavailableError):
        gmail_auth.get_gmail_service(token_path=missing)

    assert not missing.exists()


def test_pipeline_entry_points_do_not_permit_interactive_auth():
    """Static: no pipeline module may ask for interactive authorization.

    get_gmail_service is the shared door. A future edit that passes
    allow_interactive=True or force_authorize=True from a pipeline module
    would reopen this hole while both runtime tests above still pass.
    """
    import ast
    from pathlib import Path

    for module in ("daily_triage.py", "triage.py", "campaign.py"):
        tree = ast.parse(Path(module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(
                node.func, "attr", None
            )
            if name not in {"get_gmail_service", "get_credentials"}:
                continue
            passed = {kw.arg for kw in node.keywords}
            assert "allow_interactive" not in passed, (
                f"{module} asks for interactive OAuth; an unattended run "
                "must never be able to authorize"
            )
            assert "force_authorize" not in passed, (
                f"{module} forces authorization; that belongs to "
                "gmail_auth.py --authorize alone"
            )
