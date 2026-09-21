"""Enqueue due mailbox jobs and recover expired worker leases."""
from __future__ import annotations

import datetime as dt
import os

from tenant_store import PostgresTenantStore, TenantStoreError


def schedule(store, *, now=None, limit=100):
    now = now or dt.datetime.now(dt.timezone.utc)
    recovered = store.requeue_expired_jobs(now=now)
    enqueued = store.enqueue_due_jobs(now=now, limit=limit)
    return {"recovered": len(recovered), "enqueued": len(enqueued)}


def main(env=None):
    values = os.environ if env is None else env
    store = PostgresTenantStore.connect(values.get("DATABASE_URL", ""))
    try:
        result = schedule(store)
    finally:
        store.close()
    print(
        f"Scheduler complete: {result['enqueued']} queued, "
        f"{result['recovered']} recovered."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TenantStoreError as exc:
        print(f"Scheduler stopped safely ({type(exc).__name__}).")
        raise SystemExit(2)
