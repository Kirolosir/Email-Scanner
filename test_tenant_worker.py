import datetime as dt
import json
import uuid

from connection_tokens import FileKeyProvider
from mailbox_tokens import seal_mailbox_token
from tenant_store import ClaimedJob, WorkerMailbox
from tenant_worker import artifact_directory, process_one


NOW = dt.datetime(2026, 9, 21, 18, 0, tzinfo=dt.timezone.utc)


class Store:
    def __init__(self, job, mailbox, record):
        self.job = job
        self.mailbox = mailbox
        self.record = record
        self.progress = []
        self.finished = []

    def claim_next_job(self, worker_id, **_kwargs):
        assert worker_id == "worker-1"
        job, self.job = self.job, None
        return job

    def worker_mailbox(self, job_id, mailbox_id):
        assert (job_id, mailbox_id) == (self.job_id, self.mailbox.id)
        return self.mailbox

    @property
    def job_id(self):
        return self._job_id

    def worker_credentials(self, job_id, mailbox_id):
        assert (job_id, mailbox_id) == (self.job_id, self.mailbox.id)
        return self.record

    def update_job_progress(self, *args, **kwargs):
        self.progress.append((args, kwargs))

    def finish_job(self, *args, **kwargs):
        self.finished.append((args, kwargs))


def _store(tmp_path):
    mailbox_id = uuid.uuid4()
    job_id = uuid.uuid4()
    job = ClaimedJob(job_id, mailbox_id, "daily", 25, 0, 200, 1)
    mailbox = WorkerMailbox(
        mailbox_id, uuid.uuid4(), "owner@example.test", "UTC",
        dt.time(18, 0), 25, 125, 25, 1,
    )
    provider = FileKeyProvider(tmp_path / "key").create()
    record = seal_mailbox_token(
        mailbox_id, {"refresh_token": "private-refresh"}, provider
    )
    store = Store(job, mailbox, record)
    store._job_id = job_id
    return store, provider


def _artifacts(tmp_path, mailbox_id):
    directory = artifact_directory(tmp_path, mailbox_id)
    directory.mkdir(parents=True)
    for name in (
        "account.json", "taxonomy-confirmation.json",
        "ai-drafting-approval.json",
    ):
        (directory / name).write_text(json.dumps({"version": 1}))
    return directory


def test_worker_opens_only_claimed_mailbox_and_records_progress(tmp_path):
    store, provider = _store(tmp_path)
    directory = _artifacts(tmp_path, store.mailbox.id)
    seen = []

    def processor(job, mailbox, selected, token, progress):
        seen.append((job.id, mailbox.id, selected, token))
        progress(12)

    assert process_one(
        store, tmp_path, provider, processor,
        worker_id="worker-1", now=NOW,
    ) is True
    assert seen == [(
        store.job_id, store.mailbox.id, directory,
        {"refresh_token": "private-refresh"},
    )]
    assert store.progress[0][0][0:3] == (store.job_id, "worker-1", 12)
    assert store.finished[-1][1]["succeeded"] is True


def test_worker_fails_closed_when_setup_artifacts_are_missing(tmp_path):
    store, provider = _store(tmp_path)
    called = []
    assert process_one(
        store, tmp_path, provider, lambda *_args: called.append(True),
        worker_id="worker-1", now=NOW,
    ) is False
    assert called == []
    assert store.finished[-1][1] == {
        "succeeded": False, "error_code": "setup_incomplete",
    }


def test_artifact_path_uses_uuid_and_never_mailbox_address(tmp_path):
    mailbox_id = uuid.uuid4()
    path = artifact_directory(tmp_path, mailbox_id)
    assert path == tmp_path / "mailboxes" / str(mailbox_id)
    assert "@" not in str(path)
