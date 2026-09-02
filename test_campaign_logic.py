"""Offline tests for campaign.py's pure logic: address normalization,
dedupe, exclusion loading, draft MIME construction, and the draft-id
run log used by --undo. No Gmail API, no network, no auth required.

Run with:  pytest test_campaign_logic.py
"""
import base64
import datetime
import email
import os
import tempfile

import pytest
from googleapiclient.errors import HttpError

from campaign import (
    DraftLog,
    QuotaThrottle,
    build_draft_body,
    canonical_address,
    create_drafts,
    dedupe_by_sender,
    exclusions_from_labels,
    find_unresolved_placeholders,
    list_all_message_ids,
    load_aliases,
    load_draft_ids,
    load_exclusions,
    new_log_path,
    normalize_address,
    parse_args,
    preview_lines,
    select_targets,
    trash_drafts,
    _to_record,
)
import campaign


class _FakeResp:
    def __init__(self, status):
        self.status = status
        self.reason = "Not Found" if status == 404 else "Error"


def _http_error(status):
    return HttpError(_FakeResp(status), b"{}")


class _FakeGmail:
    """Minimal stand-in for the Gmail service, recording the calls
    trash_drafts() makes so the two-step draft->message->trash path can
    be verified without network or auth.

    missing_drafts / missing_messages simulate 404s.
    """

    def __init__(self, missing_drafts=(), missing_messages=()):
        self.missing_drafts = set(missing_drafts)
        self.missing_messages = set(missing_messages)
        self.trashed = []
        self.deleted = []

    # The Gmail client is a chain of builder calls; mimic just enough.
    def users(self):
        return self

    def drafts(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id, format=None):
        if id in self.missing_drafts:
            return _FakeCall(error=_http_error(404))
        return _FakeCall(result={"id": id, "message": {"id": f"msg-{id}"}})

    def trash(self, userId, id):
        if id in self.missing_messages:
            return _FakeCall(error=_http_error(404))
        self.trashed.append(id)
        return _FakeCall(result={"id": id})

    def delete(self, userId, id):
        self.deleted.append(id)
        return _FakeCall(result={})


class _FakeCall:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def execute(self):
        if self._error:
            raise self._error
        return self._result


def test_normalize_address():
    assert normalize_address("a@b.com") == "a@b.com"
    assert normalize_address("Nick Reyes <Nick@Example.COM>") == "nick@example.com"
    assert normalize_address('"Reyes, Nick" <n.reyes@x.org>') == "n.reyes@x.org"
    assert normalize_address("") == ""
    assert normalize_address(None) == ""


def test_dedupe_picks_most_recent():
    records = [
        {"sender": "kid@x.com", "internal_date": 100, "thread_id": "t1",
         "subject": "old", "rfc_message_id": "<1>", "message_id": "m1"},
        {"sender": "kid@x.com", "internal_date": 300, "thread_id": "t3",
         "subject": "newest", "rfc_message_id": "<3>", "message_id": "m3"},
        {"sender": "kid@x.com", "internal_date": 200, "thread_id": "t2",
         "subject": "middle", "rfc_message_id": "<2>", "message_id": "m2"},
        {"sender": "other@y.com", "internal_date": 50, "thread_id": "t4",
         "subject": "only", "rfc_message_id": "<4>", "message_id": "m4"},
        # The coach's own reply inside the same label.
        {"sender": "owner@example.edu", "internal_date": 999, "thread_id": "t5",
         "subject": "my reply", "rfc_message_id": "<5>", "message_id": "m5"},
        # Malformed/missing From.
        {"sender": "", "internal_date": 400, "thread_id": "t6",
         "subject": "no sender", "rfc_message_id": "<6>", "message_id": "m6"},
    ]
    result = dedupe_by_sender(records, "owner@example.edu")

    assert len(result) == 2
    assert result["kid@x.com"]["thread_id"] == "t3", "must pick most recent"
    assert "owner@example.edu" not in result, "owner's own messages must drop"
    assert "" not in result, "blank sender must drop"


def test_exclusions():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as f:
        f.write("# camp attendees\n")
        f.write("Already@Camp.com\n")
        f.write("\n")
        f.write("Second Kid <second@camp.org>\n")
        path = f.name

    exclusions = load_exclusions(path)

    assert len(exclusions) == 2, "comments and blank lines must be ignored"
    assert "already@camp.com" in exclusions, "case must be normalized"
    assert "second@camp.org" in exclusions, "display-name form must parse"
    assert load_exclusions(None) == set()


def test_build_draft_body():
    record = {
        "sender": "kid@x.com",
        "subject": "Interested in the soccer program",
        "rfc_message_id": "<abc123@mail.gmail.com>",
        "thread_id": "thread-42",
    }
    draft = build_draft_body(record, "Hi, camp registration is open.\n")

    raw = base64.urlsafe_b64decode(draft["message"]["raw"])
    parsed = email.message_from_bytes(raw)

    assert draft["message"]["threadId"] == "thread-42"
    assert parsed["To"] == "kid@x.com"
    assert parsed["Subject"] == "Re: Interested in the soccer program"
    assert parsed["In-Reply-To"] == "<abc123@mail.gmail.com>"
    assert parsed["References"] == "<abc123@mail.gmail.com>"
    assert parsed["From"] is None, "From must be unset so Gmail fills it"
    assert parsed.get_payload().strip() == "Hi, camp registration is open."

    # Already-threaded subject shouldn't get a second Re:.
    record2 = dict(record, subject="Re: Already a reply")
    parsed2 = email.message_from_bytes(
        base64.urlsafe_b64decode(build_draft_body(record2, "x")["message"]["raw"])
    )
    assert parsed2["Subject"] == "Re: Already a reply", "must not double the Re:"


def test_to_record_parses_metadata():
    message = {
        "id": "m1",
        "threadId": "t1",
        "internalDate": "1693526400000",
        "payload": {"headers": [
            {"name": "From", "value": "Nick <Nick@Example.com>"},
            {"name": "Subject", "value": "Hello"},
            {"name": "Message-ID", "value": "<xyz@mail>"},
        ]},
    }
    record = _to_record(message)

    assert record["sender"] == "nick@example.com"
    assert record["internal_date"] == 1693526400000, "must be int, not str"
    assert record["thread_id"] == "t1"
    assert record["rfc_message_id"] == "<xyz@mail>"


def test_draft_log_roundtrip():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "run.log")

    with DraftLog(path, ["run info", "label: Camp2027"]) as log:
        log.record("r100")
        log.record("r200")
        log.record("r300")

    assert log.count == 3
    assert load_draft_ids(path) == ["r100", "r200", "r300"]

    # Header comments are present in the raw file but not in parsed ids.
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    assert raw.startswith("# run info\n# label: Camp2027\n")


def test_draft_log_survives_interruption():
    """The log's whole purpose: ids written before a crash must still be
    readable, i.e. each record is flushed rather than buffered."""
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "interrupted.log")

    log = DraftLog(path, ["simulated run"])
    log.record("r1")
    log.record("r2")
    # Deliberately do NOT close - simulate the process dying here.

    assert load_draft_ids(path) == ["r1", "r2"], \
        "records must be flushed per write, not buffered"


def test_load_draft_ids_ignores_noise():
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                     encoding="utf-8") as f:
        f.write("# header line\n\n  r123  \n\n# another comment\nr456\n")
        path = f.name

    assert load_draft_ids(path) == ["r123", "r456"]


def test_log_path_is_timestamped():
    fixed = datetime.datetime(2026, 8, 31, 14, 22, 33)
    path = new_log_path(fixed)

    assert os.path.basename(path) == "campaign-20260831-142233.log"
    assert os.path.dirname(path) == "draft-logs"


def test_undo_arg_parsing():
    args = parse_args(["--undo", "draft-logs/x.log"])
    assert args.undo == "draft-logs/x.log"
    assert args.label is None, "--undo needs no label"

    args = parse_args(["Camp2027", "body.txt", "--limit", "5"])
    assert args.label == "Camp2027"
    assert args.limit == 5
    assert args.undo is None

    # Mixing --undo with a label should be rejected.
    with pytest.raises(SystemExit):
        parse_args(["Camp2027", "body.txt", "--undo", "x.log"])

    # A normal run missing body_file should be rejected.
    with pytest.raises(SystemExit):
        parse_args(["Camp2027"])


def test_trash_drafts_resolves_and_trashes():
    service = _FakeGmail()
    throttle = QuotaThrottle(units_per_second=10_000)  # no sleeping in tests
    tmpdir = tempfile.mkdtemp()
    log_path = os.path.join(tmpdir, "undo.log")

    with DraftLog(log_path) as trashed_log:
        trashed, missing, failures = trash_drafts(
            service, ["r1", "r2", "r3"], throttle, trashed_log
        )

    assert trashed == 3
    assert missing == 0
    assert failures == []
    assert service.trashed == ["msg-r1", "msg-r2", "msg-r3"], \
        "must trash the underlying message ids, not the draft ids"
    assert service.deleted == [], "drafts.delete must never be called"
    assert load_draft_ids(log_path) == ["msg-r1", "msg-r2", "msg-r3"], \
        "trashed message ids must be logged so a restore has an exact list"


def test_trash_drafts_handles_already_gone():
    """Running undo twice, or on drafts removed by hand, should report
    them as missing rather than failing the run."""
    service = _FakeGmail(missing_drafts=["r2"], missing_messages=["msg-r3"])
    throttle = QuotaThrottle(units_per_second=10_000)

    trashed, missing, failures = trash_drafts(
        service, ["r1", "r2", "r3"], throttle
    )

    assert trashed == 1
    assert missing == 2, "404s must count as missing"
    assert failures == [], "404s must not be treated as failures"
    assert service.trashed == ["msg-r1"]


def test_explicit_aliases_dedupe_known_addresses(tmp_path):
    alias_path = tmp_path / "aliases.txt"
    alias_path.write_text(
        "old@example.com,recruit@example.com\n"
        "school@example.com,recruit@example.com\n",
        encoding="utf-8",
    )
    aliases = load_aliases(alias_path)
    records = [
        {"sender": "old@example.com", "internal_date": 100, "subject": "old"},
        {"sender": "school@example.com", "internal_date": 300, "subject": "new"},
        {"sender": "other@example.com", "internal_date": 200, "subject": "other"},
    ]

    deduped = dedupe_by_sender(records, "coach@example.com", aliases)

    assert set(deduped) == {"recruit@example.com", "other@example.com"}
    assert deduped["recruit@example.com"]["subject"] == "new"
    assert canonical_address("OLD@EXAMPLE.COM", aliases) == "recruit@example.com"


def test_alias_cycles_are_rejected(tmp_path):
    path = tmp_path / "aliases.txt"
    path.write_text("a@example.com,b@example.com\nb@example.com,a@example.com\n")
    with pytest.raises(ValueError, match="cycle"):
        load_aliases(path)


def test_exclusions_are_canonicalized_with_aliases(tmp_path):
    path = tmp_path / "exclude.txt"
    path.write_text("Old Address <old@example.com>\n")
    exclusions = load_exclusions(
        path, {"old@example.com": "recruit@example.com"}
    )
    assert exclusions == {"recruit@example.com"}


def test_limits_and_preview_choose_newest():
    by_sender = {
        "a@example.com": {"sender": "a@example.com", "internal_date": 1,
                          "subject": "oldest"},
        "b@example.com": {"sender": "b@example.com", "internal_date": 3,
                          "subject": "newest"},
        "c@example.com": {"sender": "c@example.com", "internal_date": 2,
                          "subject": "excluded"},
    }
    eligible, targets = select_targets(
        by_sender, exclusions={"c@example.com"}, limit=1
    )
    assert [r["sender"] for r in eligible] == ["b@example.com", "a@example.com"]
    assert [r["sender"] for r in targets] == ["b@example.com"]
    assert preview_lines(targets) == ["b@example.com  |  newest"]


def test_campaign_placeholder_detection():
    assert find_unresolved_placeholders(
        "Register here: [Clinic Registration Link]"
    ) == ["[Clinic Registration Link]"]
    assert find_unresolved_placeholders("Final approved body https://example.test") == []


class _CampaignFake:
    def __init__(self, pages=None, records=None, draft_results=None):
        self.pages = pages or []
        self.records = records or {}
        self.draft_results = list(draft_results or [])
        self.list_calls = []
        self.created_bodies = []

    def users(self): return self
    def labels(self): return self
    def messages(self): return self
    def drafts(self): return self

    def list(self, userId, **kwargs):
        if not kwargs:
            return _FakeCall(result={"labels": [
                {"name": "Campaign", "id": "L1"},
                {"name": "Excluded", "id": "L2"},
            ]})
        token = kwargs.get("pageToken")
        self.list_calls.append(token)
        index = 0 if token is None else int(token)
        page = dict(self.pages[index])
        return _FakeCall(result=page)

    def get(self, userId, id, format=None, metadataHeaders=None):
        return _FakeCall(result=self.records[id])

    def create(self, userId, body):
        self.created_bodies.append(body)
        result = self.draft_results.pop(0)
        if isinstance(result, BaseException):
            return _FakeCall(error=result)
        return _FakeCall(result={"id": result})

    def new_batch_http_request(self, callback):
        return _FakeBatch(callback)


class _FakeBatch:
    def __init__(self, callback):
        self.callback = callback
        self.requests = []

    def add(self, request, request_id):
        self.requests.append((request_id, request))

    def execute(self):
        for request_id, request in self.requests:
            try:
                response = request.execute()
            except Exception as exc:
                self.callback(request_id, None, exc)
            else:
                self.callback(request_id, response, None)


def _record(mid, sender, date=1):
    return {
        "id": mid, "threadId": f"t-{mid}", "internalDate": str(date),
        "payload": {"headers": [
            {"name": "From", "value": sender},
            {"name": "Subject", "value": f"subject {mid}"},
            {"name": "Message-ID", "value": f"<{mid}@mail>"},
        ]},
    }


def test_fake_gmail_pagination_and_label_exclusions():
    service = _CampaignFake(
        pages=[
            {"messages": [{"id": "m1"}], "nextPageToken": "1"},
            {"messages": [{"id": "m2"}]},
        ],
        records={
            "m1": _record("m1", "One@Example.com"),
            "m2": _record("m2", "Alias@Example.com"),
        },
    )
    throttle = QuotaThrottle(units_per_second=100_000)
    assert list_all_message_ids(
        service, "Campaign", throttle, progress=False
    ) == ["m1", "m2"]
    exclusions, failures = exclusions_from_labels(
        service, ["Excluded"], throttle,
        aliases={"alias@example.com": "person@example.com"},
    )
    assert exclusions == {"one@example.com", "person@example.com"}
    assert failures == []
    assert service.list_calls == [None, "1", None, "1"]


def test_fake_gmail_draft_failure_continues_and_logs(tmp_path):
    service = _CampaignFake(draft_results=["d1", _http_error(500), "d3"])
    targets = [
        {"sender": f"r{i}@example.com", "subject": "Hello",
         "rfc_message_id": f"<{i}@mail>", "thread_id": f"t{i}"}
        for i in range(3)
    ]
    path = tmp_path / "drafts.log"
    with DraftLog(path) as log:
        created, failures = create_drafts(
            service, targets, "Approved body", QuotaThrottle(100_000), log
        )
    assert created == 2
    assert len(failures) == 1
    assert load_draft_ids(path) == ["d1", "d3"]


def test_fake_gmail_interruption_preserves_completed_draft_log(tmp_path):
    service = _CampaignFake(draft_results=["d1", KeyboardInterrupt()])
    targets = [
        {"sender": f"r{i}@example.com", "subject": "Hello",
         "rfc_message_id": f"<{i}@mail>", "thread_id": f"t{i}"}
        for i in range(2)
    ]
    path = tmp_path / "interrupted.log"
    with pytest.raises(KeyboardInterrupt):
        with DraftLog(path) as log:
            create_drafts(
                service, targets, "Approved body", QuotaThrottle(100_000), log
            )
    assert load_draft_ids(path) == ["d1"]


def test_real_write_with_placeholder_is_blocked_before_gmail(monkeypatch, tmp_path):
    body = tmp_path / "body.txt"
    body.write_text("Register: [Clinic Registration Link]")
    contacted = []
    monkeypatch.setattr(campaign, "get_gmail_service",
                        lambda: contacted.append(True))
    assert campaign.main(["2027 B TEST", str(body), "--yes"]) == 2
    assert contacted == [], "placeholder refusal must happen before Gmail auth/use"


def test_draft_log_is_owner_only(tmp_path):
    path = tmp_path / "private.log"
    with DraftLog(path) as log:
        log.record("d1")
    assert (path.stat().st_mode & 0o777) == 0o600


# --------------------------------------------------------------------
# A draft log is a rollback handle. A run that drafted nothing has
# nothing to roll back, so it must leave no file.
#
# Found live: with generic drafting off for every category, each daily
# run wrote a header-only log. Those accumulate one per day and are
# indistinguishable at a glance from a run whose drafts need review.
# --------------------------------------------------------------------

def test_a_run_with_zero_drafts_creates_no_log_file(tmp_path):
    path = tmp_path / "logs" / "daily-triage-20260902-160000.log"

    with DraftLog(path, ["daily triage", "mode: daily"]) as log:
        pass

    assert not path.exists(), (
        "a run that created no drafts left a log file behind"
    )
    assert log.count == 0
    assert log.created is False


def test_the_file_appears_only_on_the_first_recorded_draft(tmp_path):
    path = tmp_path / "logs" / "run.log"

    with DraftLog(path, ["header line"]) as log:
        assert not path.exists(), "log existed before any draft was recorded"
        log.record("r-1")
        assert path.exists(), "log missing after the first draft"
        log.record("r-2")

    body = path.read_text(encoding="utf-8")
    assert "# header line" in body, "header lost by deferring the open"
    assert load_draft_ids(path) == ["r-1", "r-2"]
    assert log.count == 2
    assert log.created is True


def test_a_deferred_log_is_still_owner_only(tmp_path):
    import os
    import stat

    path = tmp_path / "logs" / "run.log"
    with DraftLog(path, ["header"]) as log:
        log.record("r-1")

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_each_id_is_still_flushed_as_it_is_recorded(tmp_path):
    """The log has to survive a kill mid-run, so ids cannot sit in a
    buffer waiting for close()."""
    path = tmp_path / "logs" / "run.log"

    log = DraftLog(path, ["header"])
    log.record("r-1")
    # Deliberately not closed: this is the interrupted-run case.
    assert load_draft_ids(path) == ["r-1"]


def test_an_unusable_log_directory_fails_before_any_draft(tmp_path):
    """Deferring the open must not defer the failure. If the log cannot be
    written, that has to surface before a draft exists, or the run creates
    a draft with no way to roll it back.

    A regular file standing where the log directory belongs is the
    deterministic case. The other real one - a directory owned by someone
    else - cannot be built here without root, and is what the os.access
    check in __init__ covers: chmod on it raises and is swallowed, so the
    explicit check is what catches it.
    """
    import pytest

    occupied = tmp_path / "not-a-directory"
    occupied.write_text("this is a file")

    with pytest.raises(OSError):
        DraftLog(occupied / "run.log", ["header"])


def test_the_writability_preflight_rejects_an_unusable_directory(monkeypatch,
                                                                 tmp_path):
    """Directly exercise the check that covers a directory we cannot chmod."""
    import os
    import pytest

    monkeypatch.setattr(os, "access", lambda *a, **k: False)
    with pytest.raises(OSError, match="not writable"):
        DraftLog(tmp_path / "logs" / "run.log", ["header"])

    assert not (tmp_path / "logs" / "run.log").exists()


def test_a_pre_existing_log_file_is_tightened_to_0600(tmp_path):
    """os.open's mode argument is ignored when the file already exists, so
    the explicit chmod is what protects a log left behind with loose
    permissions (a crashed earlier run, a restored backup)."""
    import os
    import stat

    logs = tmp_path / "logs"
    logs.mkdir()
    path = logs / "run.log"
    path.write_text("")
    os.chmod(path, 0o644)

    with DraftLog(path, ["header"]) as log:
        log.record("r-1")

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
