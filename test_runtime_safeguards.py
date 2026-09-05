"""Offline functional and wiring tests for unattended-run safeguards."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import daily_triage
import local_notifier
import triage
from triage_limits import (
    plans_within_draft_limit,
    requires_new_draft,
    validate_scheduled_limits,
)


def _plan(message_id, draft=True, owned=False):
    return {
        "email": {"message_id": message_id},
        "template": "reply" if draft else None,
        "draft_already_owned": owned,
        "decision": SimpleNamespace(add=[]),
    }


def test_draft_limit_counts_only_new_drafts_and_keeps_non_draft_work():
    plans = [
        _plan("new-1"),
        _plan("no-draft", draft=False),
        _plan("recovered", owned=True),
        _plan("new-2"),
        _plan("new-3"),
        _plan("later-no-draft", draft=False),
    ]

    admitted, deferred = plans_within_draft_limit(plans, 2)

    assert [p["email"]["message_id"] for p in admitted] == [
        "new-1", "no-draft", "recovered", "new-2", "later-no-draft",
    ]
    assert [p["email"]["message_id"] for p in deferred] == ["new-3"]
    assert sum(requires_new_draft(p) for p in admitted) == 2


def test_zero_draft_limit_guarantees_no_new_draft_plan_is_admitted():
    plans = [_plan("a"), _plan("b", draft=False), _plan("c", owned=True)]
    admitted, deferred = plans_within_draft_limit(plans, 0)

    assert not any(requires_new_draft(p) for p in admitted)
    assert [p["email"]["message_id"] for p in deferred] == ["a"]


def test_draft_cap_precedes_write_budget_so_non_draft_work_can_continue():
    plans = [_plan("draft"), _plan("labels-only", draft=False)]

    after_drafts, deferred_drafts = plans_within_draft_limit(plans, 0)
    admitted, deferred_writes = daily_triage.plans_within_write_budget(
        after_drafts, 1
    )

    assert [p["email"]["message_id"] for p in admitted] == ["labels-only"]
    assert [p["email"]["message_id"] for p in deferred_drafts] == ["draft"]
    assert deferred_writes == []


@pytest.mark.parametrize("bad", [-1, True, 1.5, "2"])
def test_invalid_draft_limits_are_rejected(bad):
    with pytest.raises(ValueError, match="max-drafts"):
        plans_within_draft_limit([], bad)


@pytest.mark.parametrize("missing", ["max_scan", "limit", "max_drafts"])
def test_each_missing_scheduled_limit_is_rejected(missing):
    values = {"max_scan": 25, "limit": 25, "max_drafts": 5}
    values[missing] = None
    with pytest.raises(ValueError, match={
        "max_scan": "max-scan", "limit": "limit", "max_drafts": "max-drafts",
    }[missing]):
        validate_scheduled_limits(True, **values)


@pytest.mark.parametrize("omitted", ["--max-scan", "--limit", "--max-drafts"])
def test_scheduled_cli_blocks_before_gmail_when_a_limit_is_omitted(
        monkeypatch, omitted):
    contacted = []
    monkeypatch.setattr(
        daily_triage, "get_gmail_service",
        lambda **_kwargs: contacted.append(True),
    )
    argv = [
        "daily", "--scheduled", "--max-scan", "25", "--limit", "25",
        "--max-drafts", "5",
    ]
    index = argv.index(omitted)
    del argv[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        daily_triage.main(argv)

    assert caught.value.code == 2
    assert contacted == []


def test_yes_cannot_bypass_scheduled_limits(monkeypatch):
    contacted = []
    monkeypatch.setattr(
        daily_triage, "get_gmail_service",
        lambda **_kwargs: contacted.append(True),
    )
    with pytest.raises(SystemExit) as caught:
        daily_triage.main(["daily", "--scheduled", "--apply", "--yes"])
    assert caught.value.code == 2
    assert contacted == []


def test_scheduled_apply_requires_yes_so_it_never_prompts_unattended():
    with pytest.raises(SystemExit) as caught:
        daily_triage.parse_args([
            "daily", "--scheduled", "--apply",
            "--max-scan", "25", "--limit", "25", "--max-drafts", "5",
        ])
    assert caught.value.code == 2

    args = daily_triage.parse_args([
        "daily", "--scheduled", "--apply", "--yes",
        "--max-scan", "25", "--limit", "25", "--max-drafts", "5",
    ])
    assert args.scheduled and args.apply and args.yes


def test_both_triage_clis_accept_zero_as_an_explicit_draft_cap():
    assert daily_triage.parse_args(["initial", "--max-drafts", "0"]).max_drafts == 0
    assert triage.parse_args(["Some Label", "--max-drafts", "0"]).max_drafts == 0


@pytest.mark.parametrize("filename", ["daily_triage.py", "triage.py"])
def test_runtime_passes_the_real_draft_limit_to_the_planner(filename):
    tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "plans_within_draft_limit"
    ]
    assert len(calls) == 1
    assert any(
        isinstance(arg, ast.Attribute)
        and isinstance(arg.value, ast.Name)
        and arg.value.id == "args"
        and arg.attr == "max_drafts"
        for arg in calls[0].args
    ), f"{filename} must pass args.max_drafts, not a hardcoded value"


def test_daily_runtime_applies_draft_cap_before_total_write_budget():
    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    calls = {
        node.func.id: node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {
            "plans_within_draft_limit", "plans_within_write_budget",
        }
    }
    assert calls["plans_within_draft_limit"] < calls["plans_within_write_budget"]


def test_notification_uses_no_shell_and_excludes_untrusted_status_data():
    captured = []
    private_markers = [
        "PRIVATE SUBJECT", "person@example.test", "PRIVATE BODY",
        "raw-message-id", "refresh-token-value", "exception detail",
    ]
    status = {
        "last_run": {
            "counts": {"scanned": 8, "drafted": 2, "failures": 1,
                       "PRIVATE SUBJECT": 99},
            "safe_error_codes": ["draft_write_failed", *private_markers],
        }
    }

    def runner(args, **kwargs):
        captured.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    assert local_notifier.notify_failure(1, status, runner=runner)
    assert len(captured) == 1
    args, kwargs = captured[0]
    assert args[:2] == ["/usr/bin/osascript", "-e"]
    assert "shell" not in kwargs
    rendered = " ".join(args)
    assert "draft_write_failed" in rendered
    for marker in private_markers:
        assert marker not in rendered


def test_notification_failure_is_reported_without_raising():
    def runner(_args, **_kwargs):
        return SimpleNamespace(returncode=1)

    assert local_notifier.notify_failure(7, {}, runner=runner) is False


def test_unreadable_status_fails_to_empty_notification_data(monkeypatch):
    monkeypatch.setattr(
        daily_triage, "RunStatus",
        lambda _path: (_ for _ in ()).throw(OSError("private path detail")),
    )

    assert daily_triage._status_document("private-status.json") == {}


def test_failed_scheduled_run_notifies_once_and_preserves_exit(monkeypatch):
    calls = []
    monkeypatch.setattr(daily_triage, "_main_with_args", lambda *_a, **_k: 7)
    monkeypatch.setattr(daily_triage, "_status_document", lambda _p: {})
    monkeypatch.setattr(
        daily_triage, "notify_failure",
        lambda code, status: calls.append((code, status)) or False,
    )

    result = daily_triage.main([
        "daily", "--scheduled", "--max-scan", "25", "--limit", "25",
        "--max-drafts", "5", "--notify-on-failure",
    ])

    assert result == 7
    assert calls == [(7, {})]


def test_successful_scheduled_run_does_not_notify(monkeypatch):
    calls = []
    monkeypatch.setattr(daily_triage, "_main_with_args", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        daily_triage, "notify_failure", lambda *_a, **_k: calls.append(True)
    )

    result = daily_triage.main([
        "daily", "--scheduled", "--max-scan", "25", "--limit", "25",
        "--max-drafts", "5", "--notify-on-failure",
    ])

    assert result == 0
    assert calls == []


def test_unexpected_scheduled_failure_still_notifies_without_exception_text(
        monkeypatch, tmp_path):
    calls = []
    private = "PRIVATE SUBJECT person@example.test PRIVATE BODY"
    monkeypatch.setattr(
        daily_triage, "_main_with_args",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError(private)),
    )
    monkeypatch.setattr(
        daily_triage, "notify_failure",
        lambda code, status: calls.append((code, status)) or True,
    )

    result = daily_triage.main([
        "daily", "--scheduled", "--max-scan", "25", "--limit", "25",
        "--max-drafts", "5", "--notify-on-failure",
        "--status-path", str(tmp_path / "status.json"),
    ])

    assert result == 1
    assert len(calls) == 1
    assert private not in json.dumps(calls[0][1])


# --------------------------------------------------------------------
# An unattended failure must leave a real diagnostic trail.
#
# Found live: a --apply run died with outcome "failed" and the single code
# "unexpected_run_failure". The handler printed only type(exc).__name__ and
# discarded the traceback, so there was nothing on disk to debug from. The
# status file stays a PII-free summary; this is the private companion.
# --------------------------------------------------------------------

def _boom(message):
    try:
        raise ValueError(message)
    except ValueError as exc:
        return exc


def test_failure_log_records_type_message_and_traceback(tmp_path):
    import private_runtime as pr

    status = tmp_path / "state" / "daily-status.json"
    assert pr.record_failure_diagnostic(status, _boom("kaboom"), mode="daily",
                                        exit_code=1) is True

    log = pr.failure_log_path(status)
    text = log.read_text(encoding="utf-8")
    assert "ValueError" in text, "exception type missing"
    assert "kaboom" in text, "exception message missing"
    assert "Traceback (most recent call last)" in text, "traceback missing"
    assert "_boom" in text, "frame function missing"
    assert "mode=daily" in text


def test_failure_log_is_owner_only_in_a_private_directory(tmp_path):
    import os
    import stat
    import private_runtime as pr

    status = tmp_path / "state" / "daily-status.json"
    pr.record_failure_diagnostic(status, _boom("x"))
    log = pr.failure_log_path(status)

    assert stat.S_IMODE(os.stat(log).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(log.parent).st_mode) == 0o700


def test_addresses_and_credentials_are_scrubbed_from_diagnostics(tmp_path):
    import private_runtime as pr

    status = tmp_path / "state" / "daily-status.json"
    exc = _boom(
        "failed for owner@example.edu with Bearer ya29.SECRETTOKENVALUE123456"
    )
    pr.record_failure_diagnostic(status, exc)
    text = pr.failure_log_path(status).read_text(encoding="utf-8")

    assert "owner@example.edu" not in text, "an address leaked into the log"
    assert "ya29.SECRETTOKENVALUE123456" not in text, "a credential leaked"
    assert "<address:" in text, "address should be replaced by an opaque id"
    assert "ValueError" in text, "scrubbing must not destroy the diagnostic"


def test_the_same_address_scrubs_to_a_stable_id():
    """Two occurrences stay correlatable without revealing who they are."""
    import private_runtime as pr

    a = pr.scrub_diagnostic_text("from person@example.test")
    b = pr.scrub_diagnostic_text("to person@example.test")
    assert a.split("from ")[1] == b.split("to ")[1]
    assert "person@example.test" not in a


def test_recording_never_raises_when_the_log_cannot_be_written(tmp_path):
    """It runs inside an exception handler; a logging failure must not
    replace the original error."""
    import private_runtime as pr

    blocked = tmp_path / "not-a-directory"
    blocked.write_text("file where the state dir should be")

    assert pr.record_failure_diagnostic(
        blocked / "daily-status.json", _boom("x")
    ) is False


def test_the_log_rotates_instead_of_growing_without_bound(tmp_path, monkeypatch):
    import private_runtime as pr

    monkeypatch.setattr(pr, "MAX_FAILURE_LOG_BYTES", 200)
    status = tmp_path / "state" / "daily-status.json"
    for _ in range(8):
        pr.record_failure_diagnostic(status, _boom("repeated failure"))

    log = pr.failure_log_path(status)
    assert log.exists()
    assert log.stat().st_size < 200 * 6, "log grew unbounded"
    assert log.with_suffix(log.suffix + ".1").exists(), "no rotated generation"


def test_the_status_file_summary_stays_pii_free(tmp_path):
    """The diagnostic log is additive: the casually-viewed summary keeps
    exactly the PII-free shape it had."""
    import json
    import private_runtime as pr

    status_path = tmp_path / "state" / "daily-status.json"
    status = pr.RunStatus(status_path)
    status.start("daily:apply")
    status.finish(False, {"failures": 1}, ["unexpected_run_failure"])

    document = json.loads(status_path.read_text(encoding="utf-8"))
    text = json.dumps(document)
    assert "Traceback" not in text
    assert "@" not in text
    assert document["last_run"]["safe_error_codes"] == ["unexpected_run_failure"]


def test_both_handlers_write_a_diagnostic():
    """Wiring: the trail is worthless if a handler forgets to call it."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("daily_triage.py").read_text(encoding="utf-8"))
    handlers = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and any(
            isinstance(n, ast.Call)
            and getattr(n.func, "id", getattr(n.func, "attr", None)) == "finish"
            for n in ast.walk(node)
        )
        and any(
            "unexpected_run_failure" == getattr(n, "value", None)
            for n in ast.walk(node) if isinstance(n, ast.Constant)
        )
    ]
    assert handlers, "no unexpected_run_failure handler found"
    for handler in handlers:
        calls = {
            getattr(n.func, "id", None) for n in ast.walk(handler)
            if isinstance(n, ast.Call)
        }
        assert "record_failure_diagnostic" in calls, (
            "an unexpected_run_failure handler does not write a diagnostic; "
            "an unattended failure there would again leave nothing to debug"
        )


# --------------------------------------------------------------------
# Gmail retry: transient faults must be retried, dead sockets rebuilt,
# and permanent errors must NOT be slept on.
#
# Found live: 143 rate-limit rejections, then BrokenPipeError on a reused
# keep-alive socket. Gemini already retried; Gmail had nothing.
# --------------------------------------------------------------------

class _FakeResp(dict):
    """HttpError reads .status and .reason off the response object."""

    def __init__(self, status):
        super().__init__(status=status)
        self.status = status
        self.reason = "fake"


def _http_error(status, reason=None):
    from googleapiclient.errors import HttpError
    import json as _json

    content = b""
    if reason:
        content = _json.dumps(
            {"error": {"errors": [{"reason": reason}], "code": status}}
        ).encode()
    return HttpError(_FakeResp(status), content)


class _Req:
    """Minimal stand-in for a googleapiclient HttpRequest."""

    def __init__(self, outcomes, http=None):
        self.outcomes = list(outcomes)
        self.calls = 0
        self.http = http

    def execute(self):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Http:
    def __init__(self):
        self.connections = {"a": _Conn(), "b": _Conn()}


class _Conn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_rate_limit_is_retried_then_succeeds():
    import gmail_retry

    slept = []
    req = _Req([_http_error(403, "rateLimitExceeded"), {"ok": True}])
    assert gmail_retry.gmail_execute(req, sleeper=slept.append) == {"ok": True}
    assert req.calls == 2
    assert slept, "a retry must back off, not hammer immediately"


def test_permanent_403_is_not_retried():
    """403 is also permission denied. Retrying that is pure delay."""
    import pytest
    import gmail_retry
    from googleapiclient.errors import HttpError

    slept = []
    req = _Req([_http_error(403, "insufficientPermissions"), {"ok": True}])
    with pytest.raises(HttpError):
        gmail_retry.gmail_execute(req, sleeper=slept.append)
    assert req.calls == 1
    assert slept == []


def test_404_is_not_retried():
    import pytest
    import gmail_retry
    from googleapiclient.errors import HttpError

    req = _Req([_http_error(404, "notFound"), {"ok": True}])
    with pytest.raises(HttpError):
        gmail_retry.gmail_execute(req, sleeper=lambda _s: None)
    assert req.calls == 1


def test_server_errors_and_429_are_retried():
    import gmail_retry

    for status in (429, 500, 502, 503, 504):
        req = _Req([_http_error(status), {"ok": status}])
        assert gmail_retry.gmail_execute(
            req, sleeper=lambda _s: None
        ) == {"ok": status}
        assert req.calls == 2, f"{status} should have been retried"


def test_broken_pipe_is_retried_and_the_connection_is_rebuilt():
    """The live failure. Retrying without dropping the dead socket just
    fails again on the same socket."""
    import gmail_retry

    http = _Http()
    conns = list(http.connections.values())
    req = _Req([BrokenPipeError(32, "Broken pipe"), {"ok": True}], http=http)

    assert gmail_retry.gmail_execute(req, sleeper=lambda _s: None) == {"ok": True}
    assert req.calls == 2
    assert http.connections == {}, "dead connections were reused, not rebuilt"
    assert all(c.closed for c in conns), "stale sockets were not closed"


def test_every_listed_transport_fault_is_retried():
    import gmail_retry

    faults = [
        BrokenPipeError(32, "x"), ConnectionResetError(104, "x"),
        ConnectionAbortedError(103, "x"), TimeoutError("x"),
    ]
    for fault in faults:
        req = _Req([fault, {"ok": True}], http=_Http())
        assert gmail_retry.gmail_execute(req, sleeper=lambda _s: None)
        assert req.calls == 2, f"{type(fault).__name__} was not retried"


def test_retries_are_bounded_and_the_last_error_is_raised():
    import pytest
    import gmail_retry

    req = _Req([BrokenPipeError(32, "x")] * 10, http=_Http())
    with pytest.raises(BrokenPipeError):
        gmail_retry.gmail_execute(req, attempts=3, sleeper=lambda _s: None)
    assert req.calls == 3, "attempt cap not honoured"


def test_failure_records_preserve_the_real_status():
    import gmail_retry

    assert gmail_retry.describe_failure(
        _http_error(403, "rateLimitExceeded")
    ) == "403 ratelimitexceeded"
    assert gmail_retry.describe_failure(_http_error(404, "notFound")) == "404 notfound"
    assert gmail_retry.describe_failure(BrokenPipeError()) == "BrokenPipeError"


def test_every_production_gmail_call_goes_through_the_retry_layer():
    """A bare .execute() anywhere in production reopens the gap."""
    import ast
    from pathlib import Path

    modules = [
        "discovery.py", "gmail_labeler.py", "triage.py", "daily_triage.py",
        "gmail_common.py", "gmail_reader.py", "campaign.py",
        "campaign_audit.py", "gmail_auth.py", "setup_labels.py",
        "check_readiness.py",
    ]
    # `request` is the parameter inside gmail_execute itself; `batch` is a
    # BatchHttpRequest, which the helper does not wrap.
    allowed = {"request", "batch"}
    offenders = []
    for name in modules:
        tree = ast.parse(Path(name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "execute"):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and receiver.id in allowed:
                    continue
                offenders.append(f"{name}:{node.lineno}")
    assert offenders == [], (
        "unwrapped Gmail .execute() calls: " + ", ".join(offenders)
    )


# --------------------------------------------------------------------
# Truncated tracebacks must keep both ends.
# --------------------------------------------------------------------

def test_truncation_keeps_head_and_tail():
    import private_runtime as pr

    text = "OUR-FRAME" + ("x" * 20000) + "RAISE-SITE"
    out = pr._head_and_tail(text)

    assert out.startswith("OUR-FRAME"), "our own frames were lost"
    assert out.endswith("RAISE-SITE"), "the actual raise site was lost"
    assert "characters omitted" in out, "truncation was not signposted"
    assert len(out) <= pr.MAX_DETAIL_CHARS + 80


def test_short_text_is_left_exactly_alone():
    import private_runtime as pr

    assert pr._head_and_tail("Traceback: tiny") == "Traceback: tiny"


def test_triage_records_the_real_status_not_the_exception_class():
    """Wiring. describe_failure being correct is useless if the fetch loop
    still records type(exc).__name__, which is what made 143 retryable
    failures read as an undifferentiated 'HttpError'."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("triage.py").read_text(encoding="utf-8"))
    appends = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "failures"
    ]
    assert appends, "no failure records found in triage.py"
    for call in appends:
        rendered = ast.dump(call)
        assert "describe_failure" in rendered, (
            "a failure record does not use describe_failure; the real HTTP "
            "status would be lost again"
        )
        assert "'__name__'" not in rendered, (
            "a failure record still stores the bare exception class name"
        )
