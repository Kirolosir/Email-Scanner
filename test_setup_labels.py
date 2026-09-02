"""Offline tests for explicit, reviewed Gmail label creation."""
import json
from pathlib import Path

import pytest

from account_profile import load_profile
from triage_config import TriageLabelConfig, load_triage_label_config
from setup_labels import apply_label_setup, plan_label_setup


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


def test_setup_plan_is_idempotent_and_never_creates_campaign_label():
    config = _config()
    plan = plan_label_setup(
        {"YEAR_LABEL": "Y", "Example/Triage/Parent": "P"}, config
    )
    assert plan["required_existing"] == ["YEAR_LABEL"]
    assert plan["required_missing"] == []
    assert plan["already_present"] == ["Example/Triage/Parent"]
    assert "YEAR_LABEL" not in plan["create"]

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
    assert len(created) == len(config.creatable_names)
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
