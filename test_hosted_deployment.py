"""Guards on the deployment configuration itself.

A systemd unit runs with the deployment's privileges and decides what the
service may touch, so it gets guards rather than a read-through. The
properties, in the order they matter:

  D1  the service cannot start before the state disk is mounted
  D2  the state disk is the only writable path - the code is read-only
  D3  it does not run as root, and cannot regain privilege
  D4  it starts the status service, never anything that touches Gmail
  D5  it listens on loopback, not on every interface
  D6  secrets live outside the working tree, and the example holds none
"""
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).parent
UNIT = (ROOT / "hosted-status.service.example").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / "hosted.env.example").read_text(encoding="utf-8")
STATUS_SOURCE = (ROOT / "hosted_status.py").read_text(encoding="utf-8")


def _directive(name):
    """Every value given for a directive, in order."""
    return re.findall(rf"^{name}=(.*)$", UNIT, re.MULTILINE)


def _one(name):
    values = _directive(name)
    assert values, f"{name} is not set in the unit"
    return values[-1].strip()


def _exec_start():
    """ExecStart including its line continuations.

    Joined by walking lines rather than by regex: a pattern greedy enough to
    reach the end of a line also eats the trailing backslash it then needs to
    match on, which silently yields only the first line and a guard that
    inspects a fragment.
    """
    lines = UNIT.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if line.startswith("ExecStart=")), None)
    assert start is not None, "the unit has no ExecStart"

    collected = [lines[start][len("ExecStart="):]]
    while collected[-1].rstrip().endswith("\\"):
        start += 1
        collected[-1] = collected[-1].rstrip().rstrip("\\")
        collected.append(lines[start])
    return " ".join(part.strip() for part in collected)


def _state_root():
    return _one("ReadWritePaths")


# ---------------------------------------------------------------------
# D1  it cannot start before the disk is mounted
# ---------------------------------------------------------------------

def test_the_unit_refuses_to_start_before_the_state_disk_is_mounted():
    """D1: the failure the target switch introduced.

    On Cloud Run an unmounted volume meant a missing directory and the app's
    own probe caught it. On a VM the mountpoint directory still exists on the
    boot disk, is ext4, and passes every probe the process can make from
    inside itself. Only systemd can tell the difference before start-up.
    """
    assert _directive("RequiresMountsFor"), (
        "without RequiresMountsFor the service can start on an unmounted "
        "path and write the connection record to the boot disk"
    )


def test_the_mount_requirement_names_the_state_root():
    """A RequiresMountsFor for some other path guards nothing."""
    assert _one("RequiresMountsFor") == _state_root()


def test_the_application_checks_the_same_thing_independently():
    """Two layers, because this failure is silent and unrecoverable."""
    assert "HOSTED_REQUIRE_MOUNTPOINT" in STATUS_SOURCE
    assert "ismount" in STATUS_SOURCE


def test_the_mountpoint_check_defaults_to_on():
    assert 'env.get("HOSTED_REQUIRE_MOUNTPOINT", "true")' in STATUS_SOURCE


# ---------------------------------------------------------------------
# D2  only the state disk is writable
# ---------------------------------------------------------------------

def test_the_filesystem_is_read_only_apart_from_the_state_disk():
    assert _one("ProtectSystem") == "strict"
    assert _directive("ReadWritePaths") == [_state_root()], (
        "more than one writable path; the state disk should be the only one"
    )


def test_the_code_directory_is_not_writable():
    """A compromise of the service must not be able to rewrite the service."""
    working = _one("WorkingDirectory")
    for writable in _directive("ReadWritePaths"):
        assert not working.startswith(writable.rstrip("/") + "/")
        assert working != writable.rstrip("/")


def test_the_home_directory_and_tmp_are_not_shared():
    assert _one("ProtectHome") == "yes"
    assert _one("PrivateTmp") == "yes"


# ---------------------------------------------------------------------
# D3  not root, and cannot become root
# ---------------------------------------------------------------------

def test_the_service_does_not_run_as_root():
    user = _one("User")
    assert user not in ("root", "0", "")


def test_privilege_cannot_be_regained():
    assert _one("NoNewPrivileges") == "yes"


@pytest.mark.parametrize("directive", [
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups",
    "RestrictNamespaces", "LockPersonality", "MemoryDenyWriteExecute",
    "PrivateDevices",
])
def test_the_sandbox_directives_are_present(directive):
    assert _one(directive) == "yes"


def test_the_service_cannot_open_unexpected_socket_families():
    families = set(_one("RestrictAddressFamilies").split())
    assert families <= {"AF_INET", "AF_INET6", "AF_UNIX"}


# ---------------------------------------------------------------------
# D4  it runs the status service and nothing else
# ---------------------------------------------------------------------

def test_the_unit_starts_the_status_service():
    assert "hosted_wsgi:application" in _exec_start()


def test_the_unit_starts_nothing_that_touches_gmail():
    command = _exec_start()
    for forbidden in ("daily_triage", "triage.py", "campaign", "setup_labels",
                      "drafting", "gmail_", "approve_account",
                      "discover_taxonomy", "connection_archive"):
        assert forbidden not in command, (
            f"the unit's ExecStart references {forbidden}; this service is "
            "the read-only status endpoint"
        )


def test_the_unit_runs_the_service_from_a_virtualenv_not_system_python():
    """Pins the dependency set to the deployment, not to the distribution."""
    assert re.search(r"ExecStart=\S*/\.venv/bin/", UNIT)


# ---------------------------------------------------------------------
# D5  loopback only
# ---------------------------------------------------------------------

def test_the_service_binds_to_loopback_and_not_every_interface():
    """The VM target removes the need for a public listener entirely."""
    binds = re.findall(r"--bind\s+(\S+)", _exec_start())
    assert binds, "ExecStart does not specify a bind address"
    for bind in binds:
        host = bind.rsplit(":", 1)[0]
        assert host in ("127.0.0.1", "localhost", "[::1]"), (
            f"binds to {host}; this service has no reason to be reachable "
            "from outside the VM"
        )
        assert host != "0.0.0.0"


def test_the_tunnel_is_documented_since_there_is_no_public_listener():
    assert "-L" in UNIT and "ssh" in UNIT.lower()


# ---------------------------------------------------------------------
# D6  secrets
# ---------------------------------------------------------------------

def test_secrets_are_loaded_from_outside_the_working_tree():
    """An EnvironmentFile inside the checkout is a secret in the repository."""
    environment_file = _one("EnvironmentFile")
    working = _one("WorkingDirectory").rstrip("/")
    assert not environment_file.startswith(working + "/")


def test_no_secret_is_passed_on_the_command_line():
    """A command line is visible in ps output to every user on the box."""
    command = _exec_start()
    for leaked in ("BEARER", "bearer=", "--bearer", "SECRET", "password"):
        assert leaked not in command


def test_the_example_holds_no_filled_in_secret():
    for line in ENV_EXAMPLE.splitlines():
        if line.startswith("HOSTED_OPERATOR_BEARER"):
            assert line.strip() == "HOSTED_OPERATOR_BEARER="


def test_every_variable_the_service_reads_is_documented():
    for variable in re.findall(r'env\.get\("([A-Z_]+)"', STATUS_SOURCE):
        assert variable in ENV_EXAMPLE, (
            f"{variable} is read but absent from hosted.env.example"
        )


def test_the_state_root_requirement_is_stated_where_it_will_be_read():
    """The silent-data-loss traps must be documented, not only enforced."""
    assert "persistent disk" in ENV_EXAMPLE.lower()
    assert "GCS-FUSE" in ENV_EXAMPLE or "GCS FUSE" in ENV_EXAMPLE
    assert "boot disk" in ENV_EXAMPLE
    assert "boot disk" in UNIT


def test_the_check_command_is_documented_where_the_disk_is_configured():
    assert "--check-state-root" in ENV_EXAMPLE


# ---------------------------------------------------------------------
# The unit is a valid unit
# ---------------------------------------------------------------------

@pytest.mark.parametrize("section", ["[Unit]", "[Service]", "[Install]"])
def test_the_unit_has_its_sections(section):
    assert section in UNIT


def test_the_unit_restarts_on_failure():
    assert _one("Restart") == "on-failure"


def test_no_directive_sits_outside_a_section():
    seen_section = False
    for line in UNIT.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            seen_section = True
        elif stripped and not stripped.startswith("#") and "=" in stripped:
            assert seen_section, f"{stripped!r} appears before any section"


def test_the_entry_point_needs_no_environment_to_import(monkeypatch):
    for variable in ("HOSTED_STATE_ROOT", "HOSTED_OPERATOR_BEARER"):
        monkeypatch.delenv(variable, raising=False)
    import importlib

    import hosted_wsgi
    importlib.reload(hosted_wsgi)
    assert hosted_wsgi._app is None
