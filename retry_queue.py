"""Bounded private queue for mailbox work that should be attempted later."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from private_runtime import atomic_write_json, ensure_private_directory


VERSION = 1
MAX_ENTRIES = 5000
MAX_ATTEMPTS = 6
DELAYS = (300, 1800, 7200, 28800, 86400, 86400)


class RetryQueue:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = {}
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if document.get("version") == VERSION:
                for item in document.get("entries", []):
                    if (isinstance(item, dict)
                            and isinstance(item.get("message_id"), str)
                            and item["message_id"]):
                        self.entries[item["message_id"]] = item
        except (OSError, ValueError, AttributeError):
            pass

    @staticmethod
    def _timestamp(value):
        return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds")

    def due(self, now, limit):
        now_text = self._timestamp(now)
        eligible = [
            item for item in self.entries.values()
            if str(item.get("next_attempt_at", "")) <= now_text
            and int(item.get("attempts", 0)) < MAX_ATTEMPTS
        ]
        eligible.sort(key=lambda item: (item.get("next_attempt_at", ""),
                                        item.get("message_id", "")))
        return [item["message_id"] for item in eligible[:max(0, int(limit))]]

    def update(self, failed_ids=(), completed_ids=(), *, now):
        for message_id in completed_ids:
            self.entries.pop(str(message_id), None)
        for message_id in failed_ids:
            message_id = str(message_id or "")
            if not message_id:
                continue
            prior = self.entries.get(message_id, {})
            attempts = min(MAX_ATTEMPTS, int(prior.get("attempts", 0)) + 1)
            delay = DELAYS[min(attempts - 1, len(DELAYS) - 1)]
            self.entries[message_id] = {
                "message_id": message_id,
                "attempts": attempts,
                "next_attempt_at": self._timestamp(
                    now + dt.timedelta(seconds=delay)
                ),
            }
        if len(self.entries) > MAX_ENTRIES:
            ordered = sorted(
                self.entries.values(), key=lambda item: item["next_attempt_at"]
            )[-MAX_ENTRIES:]
            self.entries = {item["message_id"]: item for item in ordered}
        self.save()

    def save(self):
        ensure_private_directory(self.path.parent)
        atomic_write_json(self.path, {
            "version": VERSION,
            "entries": sorted(
                self.entries.values(), key=lambda item: item["message_id"]
            ),
        })

    def __len__(self):
        return len(self.entries)
