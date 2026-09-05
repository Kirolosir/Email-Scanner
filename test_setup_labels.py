"""Offline tests for explicit, reviewed Gmail label creation."""
import json
from pathlib import Path

import pytest

from account_profile import load_profile
from triage_config import TriageLabelConfig, load_triage_label_config
import setup_labels
from setup_labels import (
    apply_label_setup,
    confirmation_phrase,
    plan_label_setup,
)


def _config():
    return TriageLabelConfig(
        years={"2027": "YEAR_LABEL"},
        categories={
            "parent": "Example/Triage/Parent",
            "other": "Example/Triage/Other",
        },
        system={
            "needs_review": "Example/Triage/Needs Review",
            "processed": "Example/Triage/Processed",
        },
    )


class _Call:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error

    def execute(self):
        if self.error:
            raise self.error
        return self.value


class _FakeGmail:
    def __init__(self, fail_name=None):
        self.created = []
        self.fail_name = fail_name

    def users(self): return self
    def labels(self): return self

    def getProfile(self, userId):
        return _Call({"emailAddress": "owner@example.test"})

    def list(self, userId):
        return _Call({"labels": []})

    def create(self, userId, body):
        self.created.append(body)
        if body["name"] == self.fail_name:
            return _Call(error=ConnectionError("offline fake"))
        return _Call({"id": f"id-{len(self.created)}"})


def test_reviewed_config_has_exact_campaign_and_triage_labels():
    config = load_triage_label_config("label-config.example.json")
    assert config.years == {"2027": "YEAR_LABEL"}
    assert config.system["processed"] == "Example/Triage/Processed"
    assert "Example/Triage/Parent" in config.creatable_names


def test_config_rejects_wrong_2027_label_and_unreviewed_categories(tmp_path):
    source = json.loads(Path("label-config.example.json").read_text(encoding="utf-8"))
    source["years"]["2027"] = "Almost YEAR_LABEL"
    path = tmp_path / "bad-year.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly 'YEAR_LABEL'"):
        load_triage_label_config(path)

    source = json.loads(Path("label-config.example.json").read_text(encoding="utf-8"))
    source["categories"]["model_invented"] = "Invented/Label"
    path.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported model_invented"):
        load_triage_label_config(path)


def test_setup_plan_is_idempotent_and_creates_all_reviewed_labels():
    config = _config()
    plan = plan_label_setup(
        {"YEAR_LABEL": "Y", "Example/Triage/Parent": "P"}, config
    )
    assert plan["already_present"] == ["Example/Triage/Parent", "YEAR_LABEL"]
    assert "YEAR_LABEL" not in plan["create"]

    missing_all = plan_label_setup({}, config)
    assert "YEAR_LABEL" in missing_all["create"]
    assert set(missing_all["create"]) == set(config.all_names)

    complete_account = {name: name for name in config.all_names}
    assert plan_label_setup(complete_account, config)["create"] == []


def test_dry_run_makes_no_writes_and_processed_label_is_hidden():
    config = _config()
    plan = plan_label_setup({"YEAR_LABEL": "Y"}, config)
    service = _FakeGmail()

    created, failures = apply_label_setup(service, config, plan, dry_run=True)
    assert (created, failures, service.created) == ([], [], [])

    created, failures = apply_label_setup(service, config, plan, dry_run=False)
    assert failures == []
    assert len(created) == len(config.creatable_names) - 1
    processed = next(
        body for body in service.created
        if body["name"] == "Example/Triage/Processed"
    )
    assert processed["labelListVisibility"] == "labelHide"
    assert processed["messageListVisibility"] == "hide"


def test_label_creation_isolates_failures():
    config = _config()
    plan = plan_label_setup({"YEAR_LABEL": "Y"}, config)
    service = _FakeGmail(fail_name="Example/Triage/Other")
    created, failures = apply_label_setup(service, config, plan)
    assert len(created) == len(plan["create"]) - 1
    assert failures == [("Example/Triage/Other", "ConnectionError")]


def test_setup_reuses_exact_match_and_rejects_case_collision():
    config = _config()
    assert "Example/Triage/Parent" in plan_label_setup(
        {"Example/Triage/Parent": "id"}, config
    )["already_present"]
    with pytest.raises(ValueError, match="conflicts with existing"):
        plan_label_setup({"example/triage/parent": "id"}, config)


def test_apply_rejects_unreviewed_or_unbounded_plan():
    config = _config()
    with pytest.raises(ValueError, match="unreviewed"):
        apply_label_setup(_FakeGmail(), config, {"create": ["Invented"]})
    with pytest.raises(ValueError, match="bounded"):
        apply_label_setup(
            _FakeGmail(), config,
            {"create": list(config.all_names) * 21},
        )


def test_default_setup_is_offline_and_apply_requires_live(monkeypatch, tmp_path):
    config_path = _config_path = tmp_path / "account.json"
    config_path.write_text(json.dumps({
        "version": 1,
        "account": "owner@example.test",
        "timezone": "UTC",
        "taxonomy": [{
            "slug": "other", "description": "Other", "examples": [],
            "label": "Custom/Other", "drafting": {"mode": "off"},
        }],
        "system_labels": {
            "needs_review": "Custom/Needs Review",
            "processed": "Custom/Processed",
        },
    }))
    monkeypatch.setattr(
        setup_labels, "get_gmail_service",
        lambda **_kwargs: pytest.fail("offline preview contacted Gmail"),
    )
    assert setup_labels.main(["--account-config", str(_config_path)]) == 0
    assert setup_labels.main([
        "--account-config", str(_config_path), "--apply"
    ]) == 2


def test_confirmation_is_account_and_complete_set_bound():
    phrase = confirmation_phrase("owner@example.test", 5, 3)
    assert "owner@example.test" in phrase
    assert "complete set of 5" in phrase
    assert "exactly 3 missing" in phrase
    assert phrase != confirmation_phrase("other@example.test", 5, 3)
    assert phrase != confirmation_phrase("owner@example.test", 4, 3)
    assert phrase != confirmation_phrase("owner@example.test", 5, 2)


def test_live_apply_callsite_requires_exact_phrase_and_creates_complete_set(
        monkeypatch, tmp_path):
    path = tmp_path / "account.json"
    path.write_text(json.dumps({
        "version": 1,
        "account": "owner@example.test",
        "timezone": "UTC",
        "taxonomy": [{
            "slug": "other", "description": "Other", "examples": [],
            "label": "Custom/Other", "drafting": {"mode": "off"},
        }],
        "system_labels": {
            "needs_review": "Custom/Needs Review",
            "processed": "Custom/Processed",
        },
    }), encoding="utf-8")
    service = _FakeGmail()
    monkeypatch.setattr(setup_labels, "get_gmail_service", lambda **_k: service)
    argv = [
        "--account-config", str(path), "--token-path", "unused.json",
        "--live", "--apply",
    ]

    assert setup_labels.main(argv, reader=lambda _prompt: "yes") == 1
    assert service.created == []

    phrase = confirmation_phrase("owner@example.test", 3, 3)
    assert setup_labels.main(argv, reader=lambda _prompt: phrase) == 0
    assert {item["name"] for item in service.created} == {
        "Custom/Other", "Custom/Needs Review", "Custom/Processed",
    }


def test_generalized_account_uses_embedded_labels_without_legacy_config(tmp_path):
    document = {
        "version": 1,
        "account": "owner@example.test",
        "timezone": "UTC",
        "taxonomy": [{
            "slug": "project",
            "display": "Project",
            "description": "Project messages",
            "examples": [],
            "label": "Custom/Project",
            "drafting": {"mode": "off"},
        }],
        "evidence_gated_labels": [{
            "label": "Custom/2028",
            "pattern_set": "grad_year",
            "classifier_field": "grad_year",
            "expected_value": "2028",
            "require_sender_type": ["other"],
            "require_categories": ["project"],
            "min_confidence": "high",
        }],
        "system_labels": {
            "needs_review": "Custom/Needs Review",
            "processed": "Custom/Processed",
        },
    }
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    profile = load_profile(str(path))

    config = load_triage_label_config(None, profile=profile)
    assert config.years == {"2028": "Custom/2028"}
    assert config.categories == {"project": "Custom/Project"}
    assert config.system["processed"] == "Custom/Processed"
