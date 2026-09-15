"""Private, restart-safe records of Gmail changes made by one hosted run."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

from private_runtime import atomic_write_json, ensure_private_directory


VERSION = 1
GROUP_ID = re.compile(r"^[0-9]{10,16}$")
GMAIL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class RollbackJournalError(RuntimeError):
    pass


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _validate(document):
    if not isinstance(document, dict) or set(document) != {
        "version", "group_id", "created_at", "completed_at", "undone_at",
        "entries",
    }:
        raise RollbackJournalError("rollback journal structure is invalid")
    if document.get("version") != VERSION or not GROUP_ID.fullmatch(
            str(document.get("group_id", ""))):
        raise RollbackJournalError("rollback journal version or group is invalid")
    if not isinstance(document.get("entries"), list):
        raise RollbackJournalError("rollback journal entries are invalid")
    for entry in document["entries"]:
        if not isinstance(entry, dict) or set(entry) != {
            "message_id", "draft_id", "labels", "draft_undone",
            "labels_undone",
        }:
            raise RollbackJournalError("rollback journal entry is invalid")
        if not GMAIL_ID.fullmatch(str(entry.get("message_id", ""))):
            raise RollbackJournalError("rollback journal message id is invalid")
        draft_id = str(entry.get("draft_id", ""))
        if draft_id and not GMAIL_ID.fullmatch(draft_id):
            raise RollbackJournalError("rollback journal draft id is invalid")
        labels = entry.get("labels")
        if (not isinstance(labels, list)
                or not all(isinstance(label, str) and 0 < len(label) <= 225
                           for label in labels)):
            raise RollbackJournalError("rollback journal labels are invalid")
        if not isinstance(entry["draft_undone"], bool) \
                or not isinstance(entry["labels_undone"], bool):
            raise RollbackJournalError("rollback journal progress is invalid")
    return document


class RollbackJournal:
    def __init__(self, path, group_id):
        self.path = Path(path)
        if not GROUP_ID.fullmatch(str(group_id)):
            raise RollbackJournalError("rollback group is invalid")
        if self.path.exists():
            self.document = load(self.path)
            if self.document["group_id"] != str(group_id):
                raise RollbackJournalError("rollback group does not match journal")
        else:
            self.document = {
                "version": VERSION, "group_id": str(group_id),
                "created_at": _now(), "completed_at": None,
                "undone_at": None, "entries": [],
            }

    def _entry(self, message_id):
        for entry in self.document["entries"]:
            if entry["message_id"] == message_id:
                return entry
        entry = {
            "message_id": message_id, "draft_id": "", "labels": [],
            "draft_undone": False, "labels_undone": False,
        }
        self.document["entries"].append(entry)
        return entry

    def _save(self):
        ensure_private_directory(self.path.parent)
        atomic_write_json(self.path, _validate(self.document))

    def record_labels(self, message_id, labels):
        if not labels:
            return
        entry = self._entry(message_id)
        entry["labels"] = sorted(set(entry["labels"]) | set(labels))
        self._save()

    def record_draft(self, message_id, draft_id):
        if not draft_id:
            return
        self._entry(message_id)["draft_id"] = draft_id
        self._save()

    def complete(self):
        if self.document["entries"]:
            self.document["completed_at"] = _now()
            self._save()

    def mark_progress(self, message_id, *, draft=False, labels=False):
        entry = self._entry(message_id)
        entry["draft_undone"] = entry["draft_undone"] or bool(draft)
        entry["labels_undone"] = entry["labels_undone"] or bool(labels)
        self._save()

    def mark_undone(self):
        self.document["undone_at"] = _now()
        self._save()


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return _validate(json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        raise RollbackJournalError("rollback journal is unavailable") from exc


def group_documents(active, group_id):
    if not GROUP_ID.fullmatch(str(group_id)):
        raise RollbackJournalError("rollback group is invalid")
    directory = Path(active) / "rollback"
    documents = [load(path) for path in sorted(directory.glob(f"{group_id}-*.json"))]
    if not documents:
        raise RollbackJournalError("rollback group was not found")
    return documents


def group_journals(active, group_id):
    documents = group_documents(active, group_id)
    paths = sorted((Path(active) / "rollback").glob(f"{group_id}-*.json"))
    return [RollbackJournal(path, document["group_id"])
            for path, document in zip(paths, documents)]


def latest_summary(active, _allow_bootstrap=True):
    directory = Path(active) / "rollback"
    try:
        paths = sorted(directory.glob("*.json"), reverse=True)
    except OSError:
        return None
    groups = {}
    for path in paths:
        try:
            document = load(path)
        except RollbackJournalError:
            continue
        if document.get("undone_at"):
            continue
        groups.setdefault(document["group_id"], []).append(document)
    if not groups:
        if _allow_bootstrap and _bootstrap_latest_report(active):
            return latest_summary(active, _allow_bootstrap=False)
        return None
    # A background backfill can finish after a newer, short recent-mail run.
    # Completion time, rather than the numeric start id, identifies the last
    # operation the owner saw finish.
    group_id = max(
        groups,
        key=lambda value: max(
            document.get("completed_at") or document["created_at"]
            for document in groups[value]
        ),
    )
    entries = [entry for document in groups[group_id]
               for entry in document["entries"]]
    return {
        "group_id": group_id,
        "created_at": min(document["created_at"] for document in groups[group_id]),
        "messages": len(entries),
        "drafts": sum(bool(entry["draft_id"]) for entry in entries),
        "labels": sum(len(entry["labels"]) for entry in entries),
    }


def _bootstrap_latest_report(active):
    """Recover an undo boundary for the last run made before journals existed."""
    active = Path(active)
    try:
        reports = sorted(
            (path for path in (active / "review").glob("*.json") if path.is_file()),
            key=lambda path: path.stat().st_mtime, reverse=True,
        )
        if not reports:
            return False
        report = json.loads(reports[0].read_text(encoding="utf-8"))
        state = json.loads((active / "daily-state.json").read_text(encoding="utf-8"))
        if not isinstance(report, dict) or report.get("applied") is not True:
            return False
        created_at = dt.datetime.fromisoformat(str(report.get("created_at", "")))
        group_id = str(int(created_at.timestamp()))
        if not GROUP_ID.fullmatch(group_id):
            return False
        raw_messages = state.get("messages") if isinstance(state, dict) else {}
        raw_messages = raw_messages if isinstance(raw_messages, dict) else {}
        by_opaque = {
            hashlib.sha256(message_id.encode("utf-8")).hexdigest()[:16]:
            (message_id, record)
            for message_id, record in raw_messages.items()
            if isinstance(message_id, str) and isinstance(record, dict)
        }
        journal = RollbackJournal(
            active / "rollback" / f"{group_id}-00000.json", group_id
        )
        for item in report.get("messages", []):
            if not isinstance(item, dict):
                continue
            matched = by_opaque.get(item.get("opaque_message_id"))
            labels = item.get("labels")
            names = (
                labels.get("names", [])
                if isinstance(labels, dict) and labels.get("state") == "applied"
                else []
            )
            if matched is None:
                continue
            message_id, record = matched
            if names:
                journal.record_labels(message_id, names)
            if item.get("draft_created") is True and record.get("draft_id"):
                journal.record_draft(message_id, record["draft_id"])
        journal.complete()
        return bool(journal.document["entries"])
    except (OSError, ValueError, TypeError, json.JSONDecodeError,
            RollbackJournalError):
        return False
