import json
import stat

from rollback_journal import RollbackJournal, group_documents, latest_summary


def test_journal_merges_exact_changes_and_tracks_undo_progress(tmp_path):
    path = tmp_path / "rollback" / "1788969600-00000.json"
    journal = RollbackJournal(path, "1788969600")
    journal.record_labels("m1", ["Triage/Other"])
    journal.record_labels("m1", ["Triage/Processed", "Triage/Other"])
    journal.record_draft("m1", "d1")
    journal.complete()

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["entries"] == [{
        "message_id": "m1", "draft_id": "d1",
        "labels": ["Triage/Other", "Triage/Processed"],
        "draft_undone": False, "labels_undone": False,
    }]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert latest_summary(tmp_path) == {
        "group_id": "1788969600", "created_at": document["created_at"],
        "messages": 1, "drafts": 1, "labels": 2,
    }

    journal.mark_progress("m1", draft=True, labels=True)
    journal.mark_undone()
    assert latest_summary(tmp_path) is None
    assert group_documents(tmp_path, "1788969600")[0]["undone_at"]


def test_latest_summary_recovers_the_last_pre_journal_run(tmp_path):
    raw_id = "m_previous"
    opaque = __import__("hashlib").sha256(raw_id.encode()).hexdigest()[:16]
    (tmp_path / "daily-state.json").write_text(json.dumps({
        "messages": {raw_id: {"draft_id": "d_previous"}},
    }), encoding="utf-8")
    review = tmp_path / "review"
    review.mkdir()
    (review / "latest.json").write_text(json.dumps({
        "created_at": "2026-09-09T16:00:00+00:00", "applied": True,
        "messages": [{
            "opaque_message_id": opaque, "draft_created": True,
            "labels": {"state": "applied", "names": ["Triage/Processed"]},
        }],
    }), encoding="utf-8")

    summary = latest_summary(tmp_path)

    assert summary["messages"] == 1
    assert summary["drafts"] == 1
    assert summary["labels"] == 1


def test_completed_undo_does_not_rebuild_or_recurse_from_old_report(tmp_path):
    raw_id = "m_previous"
    opaque = __import__("hashlib").sha256(raw_id.encode()).hexdigest()[:16]
    (tmp_path / "daily-state.json").write_text(json.dumps({
        "messages": {raw_id: {"draft_id": "d_previous"}},
    }), encoding="utf-8")
    review = tmp_path / "review"
    review.mkdir()
    (review / "latest.json").write_text(json.dumps({
        "created_at": "2026-09-09T16:00:00+00:00", "applied": True,
        "messages": [{
            "opaque_message_id": opaque, "draft_created": True,
            "labels": {"state": "applied", "names": ["Triage/Processed"]},
        }],
    }), encoding="utf-8")
    path = tmp_path / "rollback" / "1788969600-00000.json"
    journal = RollbackJournal(path, "1788969600")
    journal.record_labels(raw_id, ["Triage/Processed"])
    journal.record_draft(raw_id, "d_previous")
    journal.complete()
    journal.mark_undone()

    assert latest_summary(tmp_path) is None


def test_rollback_summary_includes_every_item_in_a_large_run(tmp_path):
    journal = RollbackJournal(
        tmp_path / "rollback" / "1788969600-00000.json", "1788969600"
    )
    for index in range(150):
        message_id = f"m{index}"
        journal.record_labels(
            message_id, ["Triage/Processed", "Triage/Recruit"]
        )
        journal.record_draft(message_id, f"d{index}")
    journal.complete()

    assert latest_summary(tmp_path) | {"created_at": None} == {
        "group_id": "1788969600", "created_at": None,
        "messages": 150, "drafts": 150, "labels": 300,
    }


def test_latest_completed_group_wins_when_backfill_finishes_after_recent_run(
        tmp_path):
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    base = {
        "version": 1, "undone_at": None,
        "entries": [{
            "message_id": "m1", "draft_id": "d1", "labels": [],
            "draft_undone": False, "labels_undone": False,
        }],
    }
    older = dict(base, group_id="1788969600",
                 created_at="2026-09-09T16:00:00+00:00",
                 completed_at="2026-09-09T18:00:00+00:00")
    recent = dict(base, group_id="1788973200",
                  created_at="2026-09-09T17:00:00+00:00",
                  completed_at="2026-09-09T17:05:00+00:00")
    (rollback / "1788969600-00000.json").write_text(
        json.dumps(older), encoding="utf-8"
    )
    (rollback / "1788973200-00000.json").write_text(
        json.dumps(recent), encoding="utf-8"
    )

    assert latest_summary(tmp_path)["group_id"] == "1788969600"
