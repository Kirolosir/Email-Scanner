import json

import pytest

import connection
import hosted_settings as settings


A = "owner@example.test"


def _form(**changes):
    form = {
        "labels": "Scheduling | AI/Scheduling\nFinance | AI/Finance",
        "timezone": "America/New_York",
        "run_at": "18:00",
        "display_name": "Owner",
        "signature": "Owner",
        "max_scan": "50",
        "limit": "40",
        "max_drafts": "8",
        "confirm_unsent_drafts": "yes",
    }
    form.update(changes)
    return form


def test_label_lines_create_safe_categories_and_other_fallback():
    categories = settings.parse_label_lines(_form()["labels"])
    assert [item["slug"] for item in categories] == [
        "scheduling", "finance", "other"
    ]
    assert categories[0]["label"] == "AI/Scheduling"


def test_invalid_and_duplicate_labels_are_refused():
    with pytest.raises(settings.SettingsError):
        settings.parse_label_lines("Inbox")
    with pytest.raises(settings.SettingsError, match="duplicate"):
        settings.parse_label_lines("Finance | AI/Money\nfinance | AI/Other")


def test_saving_settings_writes_a_complete_approved_bundle(tmp_path):
    connection.connect(tmp_path, A)
    updated = settings.save_settings(tmp_path, _form())
    active = updated.directory
    for name in (
        "account.json", "taxonomy-confirmation.json",
        "ai-drafting-approval.json", settings.PENDING_LABEL_SETUP,
    ):
        assert (active / name).is_file()
    assert updated.enabled is True
    assert updated.timezone_name == "America/New_York"
    assert (updated.max_scan, updated.limit, updated.max_drafts) == (
        50, 50 * settings.MAX_WRITES_PER_MESSAGE, 50,
    )

    config = json.loads((active / "account.json").read_text())
    approval = json.loads((active / "ai-drafting-approval.json").read_text())
    pending = json.loads((active / settings.PENDING_LABEL_SETUP).read_text())
    assert approval["draft_all_replyable_messages"] is True
    assert len(approval["policy_digest"]) == 64
    int(approval["policy_digest"], 16)
    assert pending["account_config_digest"] == settings.document_digest(config)
    assert config["ai_drafting"]["default_guidance"] == (
        settings.DEFAULT_DRAFT_GUIDANCE
    )


def test_draft_voice_is_editable_and_bounded(tmp_path):
    connection.connect(tmp_path, A)
    settings.save_settings(
        tmp_path, _form(draft_guidance="Warm, direct, and conversational.")
    )
    config = json.loads(
        (tmp_path / "active" / "account.json").read_text(encoding="utf-8")
    )
    assert config["ai_drafting"]["default_guidance"] == (
        "Warm, direct, and conversational."
    )

    with pytest.raises(settings.SettingsError, match="under 1200"):
        settings.build_settings_document(
            connection.current(tmp_path),
            _form(draft_guidance="x" * 1201),
        )


def test_one_batch_size_derives_complete_bounded_run_limits(tmp_path):
    occupant = connection.connect(tmp_path, A)
    _document, _profile, _run_at, limits = settings.build_settings_document(
        occupant, _form(max_scan="75", limit="1", max_drafts="0")
    )
    assert limits == {
        "max_scan": 75,
        "limit": 75 * settings.MAX_WRITES_PER_MESSAGE,
        "max_drafts": 75,
    }
    with pytest.raises(settings.SettingsError, match="scan limit"):
        settings.build_settings_document(
            occupant, _form(max_scan=str(settings.MAX_MESSAGES_PER_RUN + 1))
        )


def test_maximum_daily_batch_can_draft_every_scanned_message(tmp_path):
    occupant = connection.connect(tmp_path, A)
    _document, profile, _run_at, limits = settings.build_settings_document(
        occupant, _form(max_scan=str(settings.MAX_MESSAGES_PER_RUN))
    )

    assert settings.MAX_MESSAGES_PER_RUN == 2000
    assert profile.draft_all_replyable_messages is True
    assert limits == {
        "max_scan": 2000,
        "limit": 2000 * settings.MAX_WRITES_PER_MESSAGE,
        "max_drafts": 2000,
    }


def test_unconfirmed_drafts_change_nothing(tmp_path):
    connection.connect(tmp_path, A)
    before = (tmp_path / "connection.json").read_bytes()
    with pytest.raises(settings.SettingsError, match="unsent drafts"):
        settings.save_settings(
            tmp_path, _form(confirm_unsent_drafts="")
        )
    assert (tmp_path / "connection.json").read_bytes() == before
    assert not (tmp_path / "active" / "account.json").exists()


def test_partial_bundle_write_leaves_scheduled_runs_disabled(tmp_path,
                                                              monkeypatch):
    connection.connect(tmp_path, A)
    real_write = settings.atomic_write_json
    calls = []

    def fail_third(path, document):
        calls.append(path)
        if len(calls) == 3:
            raise OSError("disk failed")
        return real_write(path, document)

    monkeypatch.setattr(settings, "atomic_write_json", fail_third)
    with pytest.raises(settings.SettingsError, match="remain paused"):
        settings.save_settings(tmp_path, _form())
    assert connection.current(tmp_path).enabled is False
    assert not (tmp_path / "active" / settings.PENDING_LABEL_SETUP).exists()


def test_settings_cannot_change_the_connected_identity(tmp_path):
    seat = connection.connect(tmp_path, A)
    settings.save_settings(tmp_path, _form())
    assert connection.current(tmp_path).account == seat.account == A
