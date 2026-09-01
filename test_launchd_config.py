"""Static offline checks for the prepared, inactive macOS schedule."""
import plistlib
from pathlib import Path


PLIST = Path("launchd/com.example.email.daily-triage.plist.example")


def test_launchd_example_is_6pm_absolute_and_contains_no_secrets():
    with PLIST.open("rb") as plist_file:
        config = plistlib.load(plist_file)
    assert config["StartCalendarInterval"] == {"Hour": 18, "Minute": 0}
    arguments = config["ProgramArguments"]
    assert all(value.startswith("/") for value in arguments[:2])
    assert "daily" in arguments
    assert "--apply" in arguments and "--yes" in arguments
    assert "--scheduled" in arguments
    assert "/Users/kirolos/Documents/Email-Scanner/tokens/coach.json" in arguments
    assert "EnvironmentVariables" not in config
    assert "/automation-logs/" in config["StandardOutPath"]
    assert "/automation-logs/" in config["StandardErrorPath"]

    text = PLIST.read_text(encoding="utf-8").lower()
    for forbidden in ("access_token", "refresh_token", "client_secret", "api_key"):
        assert forbidden not in text
