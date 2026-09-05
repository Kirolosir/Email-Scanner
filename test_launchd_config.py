"""Static offline checks for the prepared, inactive macOS schedule."""
import plistlib
from pathlib import Path


PLISTS = sorted(Path("launchd").glob("*.plist*"))


def _argument_value(arguments, flag):
    return arguments[arguments.index(flag) + 1]


def test_every_prepared_launchd_file_is_bounded_6pm_and_secret_free():
    assert PLISTS
    for plist_path in PLISTS:
        with plist_path.open("rb") as plist_file:
            config = plistlib.load(plist_file)
        assert config["StartCalendarInterval"] == {"Hour": 18, "Minute": 0}
        arguments = config["ProgramArguments"]
        assert all(value.startswith("/") for value in arguments[:2])
        assert "daily" in arguments
        assert "--apply" in arguments and "--yes" in arguments
        assert "--scheduled" in arguments
        assert "--notify-on-failure" in arguments
        assert _argument_value(arguments, "--max-scan") == "25"
        assert _argument_value(arguments, "--limit") == "25"
        assert _argument_value(arguments, "--max-drafts") == "5"
        # Pinned to a named token so a scheduled run cannot silently fall
        # back to an implicit token. The account-specific local copy may use
        # a different reviewed filename from the public example.
        token_path = _argument_value(arguments, "--token-path")
        assert token_path.startswith("/") and token_path.endswith(".json")
        assert "EnvironmentVariables" not in config
        assert "/automation-logs/" in config["StandardOutPath"]
        assert "/automation-logs/" in config["StandardErrorPath"]

        text = plist_path.read_text(encoding="utf-8").lower()
        for forbidden in (
            "access_token", "refresh_token", "client_secret", "api_key",
        ):
            assert forbidden not in text
