"""Repository hygiene checks for authorship and accidental bulk artifacts."""
from pathlib import Path
import subprocess


ROOT = Path(__file__).parent
MAX_TRACKED_FILE_BYTES = 512 * 1024
FORBIDDEN_BRANDS = ("co" + "dex", "clau" + "de code")


def _tracked_files():
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / item.decode("utf-8")
            for item in result.stdout.split(b"\0") if item]


def test_no_agent_brand_is_present_in_tracked_project_content():
    offenders = []
    for path in _tracked_files():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").casefold()
        if any(brand in text for brand in FORBIDDEN_BRANDS):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_no_large_binary_or_sdk_artifact_is_tracked():
    oversized = [
        path.relative_to(ROOT).as_posix() for path in _tracked_files()
        if path.is_file() and path.stat().st_size > MAX_TRACKED_FILE_BYTES
    ]
    assert oversized == []
    tracked = {path.relative_to(ROOT).as_posix() for path in _tracked_files()}
    assert not any(
        name == "google-cloud-sdk" or name.startswith("google-cloud-sdk/")
        or name == "gcloud --version" or name.startswith("gcloud --version/")
        for name in tracked
    )
