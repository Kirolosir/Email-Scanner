import datetime as dt

from tenant_scheduler import schedule


NOW = dt.datetime(2026, 9, 21, 18, 0, tzinfo=dt.timezone.utc)


class Store:
    def __init__(self):
        self.calls = []

    def requeue_expired_jobs(self, **kwargs):
        self.calls.append(("recover", kwargs))
        return ["job-1"]

    def enqueue_due_jobs(self, **kwargs):
        self.calls.append(("enqueue", kwargs))
        return ["job-2", "job-3"]


def test_scheduler_recovers_leases_before_enqueuing_due_mailboxes():
    store = Store()
    assert schedule(store, now=NOW, limit=25) == {
        "recovered": 1, "enqueued": 2,
    }
    assert store.calls == [
        ("recover", {"now": NOW}),
        ("enqueue", {"now": NOW, "limit": 25}),
    ]
