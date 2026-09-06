"""Offline tests for check_readiness.py's JSON snapshot mode.

The snapshot is what the local status page displays, so it is a published
artifact: its schema is fixed, it is written with the same private-file
discipline as every other artifact in the system, and it carries nothing the
text renderer did not already print to a terminal.
"""
import ast
import json
import os
import stat
from pathlib import Path

import pytest

import check_readiness
from readiness import CheckResult, ReadinessReport


def _report(ready=True, live=False):
    report = ReadinessReport(account="owner@example.test", live=live)
    report.results = [
        CheckResult("account config", True, "loaded 8 categories", True),
        CheckResult("taxonomy confirmed", ready, "all 8 confirmed", True),
        CheckResult("campaign approval", False, "not used here", False),
    ]
    return report


def test_document_matches_the_published_schema():
    document = check_readiness.report_to_document(_report())
    assert set(document) == {
        "version", "created_at", "account", "live", "ready", "status", "results",
    }
    assert document["version"] == check_readiness.READINESS_SNAPSHOT_VERSION
    assert document["ready"] is True and document["status"] == "ready"
    for item in document["results"]:
        assert set(item) == {"name", "ok", "required", "detail"}
        assert isinstance(item["ok"], bool)
        assert isinstance(item["required"], bool)


def test_not_ready_is_reported_as_such():
    document = check_readiness.report_to_document(_report(ready=False))
    assert document["ready"] is False
    assert document["status"] == "not_ready"


def test_document_is_json_serializable_and_stable():
    document = check_readiness.report_to_document(_report())
    reloaded = json.loads(json.dumps(document))
    assert reloaded == document


def test_optional_failure_does_not_make_the_report_not_ready():
    """A skipped optional check must not read as a blocking failure."""
    document = check_readiness.report_to_document(_report())
    optional = [r for r in document["results"] if not r["required"]]
    assert optional and optional[0]["ok"] is False
    assert document["ready"] is True


class _Args:
    def __init__(self, json_output=None):
        self.json = True
        self.json_output = json_output


def test_snapshot_is_written_private_and_readable(tmp_path, capsys):
    target = tmp_path / "state" / "readiness.json"
    check_readiness._emit(_report(), _Args(json_output=str(target)))

    assert target.exists()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600, (
        "the readiness snapshot must be owner-only like every other artifact"
    )
    assert stat.S_IMODE(os.stat(target.parent).st_mode) == 0o700
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["account"] == "owner@example.test"
    # It is also echoed, so a piped invocation still works.
    assert json.loads(capsys.readouterr().out)["account"] == "owner@example.test"


def test_json_without_output_only_prints(tmp_path, capsys):
    check_readiness._emit(_report(), _Args())
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "ready"
    assert list(tmp_path.iterdir()) == []


def test_text_mode_is_unchanged_by_the_json_addition(capsys):
    class TextArgs:
        json = False
        json_output = None

    check_readiness._emit(_report(), TextArgs())
    out = capsys.readouterr().out
    assert "Account: owner@example.test" in out
    assert "[PASS] account config" in out
    assert out.lstrip().startswith("Account:"), "text mode emitted JSON"


def test_json_output_requires_json(capsys):
    with pytest.raises(SystemExit) as caught:
        check_readiness.parse_args([
            "--account-config", "a.json", "--taxonomy-confirmation", "t.json",
            "--json-output", "out.json",
        ])
    assert caught.value.code == 2


def test_json_flags_parse_together():
    args = check_readiness.parse_args([
        "--account-config", "a.json", "--taxonomy-confirmation", "t.json",
        "--json", "--json-output", "out.json",
    ])
    assert args.json is True and args.json_output == "out.json"


def test_snapshot_carries_no_token_path_or_credential(tmp_path):
    """The snapshot is published to a browser; it must not name secrets."""
    target = tmp_path / "readiness.json"
    check_readiness._emit(_report(), _Args(json_output=str(target)))
    text = target.read_text(encoding="utf-8").lower()
    for forbidden in ("refresh_token", "access_token", "client_secret",
                      "api_key", "ya29.", "gocspx-"):
        assert forbidden not in text


def test_live_failure_path_never_writes_a_snapshot():
    """Live Gmail failure prints to the terminal and returns before _emit.

    The exception text there can name a token path, so it must not reach the
    artifact a browser renders.
    """
    tree = ast.parse(Path("check_readiness.py").read_text(encoding="utf-8"))
    main = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    handlers = [
        node for node in ast.walk(main) if isinstance(node, ast.ExceptHandler)
    ]
    assert handlers, "expected a guarded live-metadata call"
    for handler in handlers:
        called = {
            getattr(n.func, "id", None) for n in ast.walk(handler)
            if isinstance(n, ast.Call)
        }
        assert "_emit" not in called, (
            "a live-failure handler writes the snapshot; its exception text "
            "can name a token path"
        )
