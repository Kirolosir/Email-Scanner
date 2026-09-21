import datetime as dt
import uuid

from tenant_processor import TenantMailboxProcessor
from tenant_store import ClaimedJob, WorkerMailbox


class Request:
    def execute(self):
        return {"emailAddress": "owner@example.test"}


class Service:
    def users(self):
        return self

    def getProfile(self, **_kwargs):
        return Request()


class Triage:
    def __init__(self):
        self.calls = []
        self.last_result = {}

    def __call__(self, argv, *, gmail_service, message_ids_override=None,
                 gmail_write_services=None):
        self.calls.append({
            "argv": argv,
            "service": gmail_service,
            "ids": message_ids_override,
            "writers": gmail_write_services,
        })
        selected = message_ids_override or ["daily-1", "daily-2"]
        self.last_result = {"completed_ids": selected, "failed_ids": []}
        return 0


def _mailbox():
    return WorkerMailbox(
        uuid.uuid4(), uuid.uuid4(), "owner@example.test", "UTC",
        dt.time(18, 0), 25, 5000, 5000, 1,
    )


def _processor(triage, ids=None):
    service = Service()
    return TenantMailboxProcessor(
        "client.json",
        service_builder=lambda *_args, **_kwargs: service,
        credential_refresher=lambda _credentials: None,
        credential_builder=lambda _token, _path: object(),
        triage_main=triage,
        history_lister=lambda *_args, **_kwargs: list(ids or []),
    )


def _artifacts(directory):
    directory.mkdir(parents=True)
    for name in (
        "account.json", "taxonomy-confirmation.json",
        "ai-drafting-approval.json",
    ):
        (directory / name).write_text("{}")


def test_daily_job_uses_only_mailbox_scoped_paths(tmp_path):
    mailbox = _mailbox()
    directory = tmp_path / "mailboxes" / str(mailbox.id)
    _artifacts(directory)
    triage = Triage()
    processor = _processor(triage)
    job = ClaimedJob(uuid.uuid4(), mailbox.id, "daily", 25, 0, 200, 1)
    progress = []

    processor(job, mailbox, directory, {"refresh_token": "secret"}, progress.append)

    assert progress == [2]
    argv = triage.calls[0]["argv"]
    paths = [value for value in argv if str(directory) in value]
    assert paths and all(str(directory) in value for value in paths)
    assert mailbox.address not in " ".join(argv)
    assert len(triage.calls[0]["writers"]) == 4


def test_backfill_is_grouped_and_resumes_from_saved_offset(tmp_path):
    mailbox = _mailbox()
    directory = tmp_path / "mailboxes" / str(mailbox.id)
    _artifacts(directory)
    ids = [f"m-{number}" for number in range(450)]
    triage = Triage()
    processor = _processor(triage, ids)
    job = ClaimedJob(uuid.uuid4(), mailbox.id, "backfill", 450, 200, 200, 2)
    progress = []

    processor(job, mailbox, directory, {"refresh_token": "secret"}, progress.append)

    assert [len(call["ids"]) for call in triage.calls] == [200, 50]
    assert triage.calls[0]["ids"][0] == "m-200"
    assert progress == [400, 450]
    assert (directory / "jobs" / f"{job.id}.json").is_file()
