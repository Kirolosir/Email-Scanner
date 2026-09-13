"""Offline tests for the go-live readiness checker.

The property that matters: it must never report ready when a precondition is
unmet, including when a check cannot be completed at all. "Unknown" is not a
pass. Gmail is never contacted here - the authenticated account and label list
are passed in.
"""
import itertools
import json
import os
from pathlib import Path

import pytest

import check_readiness
import drafting
import readiness
from readiness import CheckResult, ReadinessReport, build_report
from taxonomy import proposal_digest

ACCOUNT = "owner@example.test"
REAL_TEMPLATE = "Reviewed fixed wording for this category.\n"


def _private_state_dir(tmp_path):
    """A per-test 0700 state directory.

    Every config built here must set one. Without it state_dir defaults to
    the relative "triage-state", so the readiness check inspects the repo
    checkout's own directory: the suite passed only while that directory
    happened not to exist, and the first real dry run created it 0755 and
    broke five unrelated tests.
    """
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state_dir, 0o700)
    return state_dir


def _config(tmp_path, modes=None, labels=True):
    modes = modes or {"recruiting": "off"}
    taxonomy = []
    for slug, mode in modes.items():
        entry = {"slug": slug, "description": f"{slug} mail",
                 "examples": [f"{slug} subject"],
                 "drafting": {"mode": mode}}
        if labels:
            entry["label"] = f"Triage/{slug}"
        taxonomy.append(entry)
    document = {"version": 1, "account": ACCOUNT, "timezone": "UTC",
                "taxonomy": taxonomy,
                "paths": {"state_dir": str(_private_state_dir(tmp_path))}}
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return str(path)


_confirmation_seq = itertools.count()


def _confirmation(tmp_path, config_path, slugs=None):
    """Each call gets its own file.

    A shared filename made a partial confirmation invisible: the full
    confirmation written later overwrote it, so a test that meant to check
    "one category unconfirmed" was silently checking "all confirmed" and
    passed for the wrong reason.
    """
    from account_profile import load_profile
    profile = load_profile(config_path)
    entries = {
        entry["slug"]: entry["digest"] for entry in profile.taxonomy
        if slugs is None or entry["slug"] in slugs
    }
    path = tmp_path / f"taxonomy-confirmation-{next(_confirmation_seq)}.json"
    path.write_text(json.dumps({"version": 1, "account": ACCOUNT,
                                "confirmed_categories": entries}))
    return str(path)


def _ai_approval(tmp_path, categories, allow_protected=False):
    path = tmp_path / "ai.json"
    path.write_text(json.dumps({
        "version": 1, "account": ACCOUNT,
        "approved_categories": sorted(categories),
        "allow_protected_labels": allow_protected,
        "acknowledgement": drafting.AI_DRAFTING_ACKNOWLEDGEMENT,
    }))
    return str(path)


def _labels(config_path):
    from account_profile import load_profile
    profile = load_profile(config_path)
    names = {e["label"] for e in profile.taxonomy if e.get("label")}
    names |= set(profile.protected_labels)
    return {name: f"Label_{i}" for i, name in enumerate(sorted(names))}


def _report(tmp_path, **overrides):
    config = overrides.pop("config", None) or _config(tmp_path)
    kwargs = dict(
        config_path=config,
        confirmation_path=_confirmation(tmp_path, config),
        ai_approval_path=None,
        templates_dir="templates",
        template_approval_path=None,
        authenticated_account=ACCOUNT,
        account_labels=_labels(config),
    )
    kwargs.update(overrides)
    return build_report(**kwargs)


# --------------------------------------------------------------------
# The baseline: a fully-configured account reports ready
# --------------------------------------------------------------------

def test_a_fully_configured_account_is_ready(tmp_path):
    """Control. Without this, every negative test below could pass simply
    because the checker never reports ready at all."""
    report = _report(tmp_path)

    assert report.ready is True, report.render()
    assert report.status == readiness.READY
    assert report.blocking == []


# --------------------------------------------------------------------
# Each unmet precondition must block
# --------------------------------------------------------------------

def test_missing_account_config_blocks(tmp_path):
    report = _report(tmp_path, config_path=str(tmp_path / "nope.json"))
    assert report.ready is False
    assert any("account config" in r.name for r in report.blocking)


def test_no_account_config_supplied_blocks(tmp_path):
    assert _report(tmp_path, config_path=None).ready is False


def test_config_for_a_different_account_blocks(tmp_path):
    report = _report(tmp_path, authenticated_account="someone@else.test")
    assert report.ready is False
    assert any("binding" in r.name for r in report.blocking)


def test_unconfirmed_taxonomy_blocks(tmp_path):
    config = _config(tmp_path, {"recruiting": "off", "marketing": "off"})
    report = _report(
        tmp_path, config=config,
        confirmation_path=_confirmation(tmp_path, config, slugs={"recruiting"}),
        account_labels=_labels(config),
    )
    assert report.ready is False
    blocking = " ".join(r.detail for r in report.blocking)
    assert "marketing" in blocking


def test_absent_confirmation_file_blocks(tmp_path):
    report = _report(tmp_path, confirmation_path=None)
    assert report.ready is False


def test_generic_mode_without_ai_approval_blocks(tmp_path):
    config = _config(tmp_path, {"recruiting": "generic"})
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config),
                     ai_approval_path=None,
                     account_labels=_labels(config))
    assert report.ready is False
    assert any("Generated drafting" in r.name for r in report.blocking)


def test_generic_mode_with_ai_approval_is_ready(tmp_path):
    config = _config(tmp_path, {"recruiting": "generic"})
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config),
                     ai_approval_path=_ai_approval(tmp_path, {"recruiting"}),
                     account_labels=_labels(config))
    assert report.ready is True, report.render()


def test_ai_approval_covering_the_wrong_category_blocks(tmp_path):
    config = _config(tmp_path, {"recruiting": "generic", "marketing": "generic"})
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config),
                     ai_approval_path=_ai_approval(tmp_path, {"recruiting"}),
                     account_labels=_labels(config))
    assert report.ready is False
    assert "marketing" in " ".join(r.detail for r in report.blocking)


def test_protected_generic_category_requires_the_larger_grant(tmp_path):
    """Mutation pin: passing carries_protected_label=False would make the
    first report incorrectly ready even though the runtime would refuse it."""
    document = {
        "version": 1,
        "account": ACCOUNT,
        "timezone": "UTC",
        "taxonomy": [{
            "slug": "recruiting",
            "description": "Recruit messages",
            "examples": ["Recruit subject"],
            "label": "Triage/Recruiting",
            "expected_sender": "recruit",
            "drafting": {"mode": "generic"},
        }],
        "protected_labels": ["Protected/Recruiting"],
        "evidence_gated_labels": [{
            "label": "Protected/Recruiting",
            "pattern_set": "grad_year",
            "classifier_field": "grad_year",
            "expected_value": "2031",
            "require_sender_type": ["recruit"],
            "require_categories": ["recruiting"],
            "min_confidence": "high",
        }],
        "paths": {"state_dir": str(_private_state_dir(tmp_path))},
    }
    config_path = tmp_path / "protected-account.json"
    config_path.write_text(json.dumps(document))
    config = str(config_path)
    common = dict(
        config=config,
        confirmation_path=_confirmation(tmp_path, config),
        account_labels=_labels(config),
    )

    blocked = _report(
        tmp_path,
        ai_approval_path=_ai_approval(tmp_path, {"recruiting"}),
        **common,
    )
    assert blocked.ready is False
    assert "protected-label" in " ".join(
        result.detail for result in blocked.blocking
    )

    allowed_path = tmp_path / "ai-protected.json"
    allowed_path.write_text(json.dumps({
        "version": 1,
        "account": ACCOUNT,
        "approved_categories": ["recruiting"],
        "allow_protected_labels": True,
        "acknowledgement": drafting.AI_DRAFTING_ACKNOWLEDGEMENT,
    }))
    allowed = _report(
        tmp_path, ai_approval_path=str(allowed_path), **common
    )
    assert allowed.ready is True, allowed.render()


def test_template_mode_with_a_placeholder_blocks(tmp_path):
    """All shipped templates are placeholders, so template mode on one of
    them must block."""
    config = _config(tmp_path, {"recruit_intro": "template"})
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config),
                     account_labels=_labels(config))
    assert report.ready is False
    assert "placeholder" in " ".join(r.detail for r in report.blocking)


def test_template_mode_without_a_template_file_blocks(tmp_path):
    config = _config(tmp_path, {"nosuchcategory": "template"})
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config),
                     account_labels=_labels(config))
    assert report.ready is False
    assert "no template file" in " ".join(r.detail for r in report.blocking)


def test_missing_gmail_labels_block(tmp_path):
    report = _report(tmp_path, account_labels={})
    assert report.ready is False
    assert any("labels" in r.name for r in report.blocking)


def test_unreadable_label_list_blocks(tmp_path):
    """A label list that could not be fetched is not evidence of anything."""
    report = _report(tmp_path, account_labels=None)
    assert report.ready is False


def test_unknown_authenticated_account_blocks(tmp_path):
    assert _report(tmp_path, authenticated_account="").ready is False


def test_offline_report_skips_live_checks_without_claiming_live_readiness(tmp_path):
    config = _config(tmp_path)
    report = build_report(
        config, _confirmation(tmp_path, config), None, "templates", None,
        ACCOUNT, None, live=False,
    )

    assert report.ready is True, report.render()
    assert "OFFLINE READY" in report.render()
    skipped = {result.name for result in report.results if not result.required}
    assert skipped == {"authenticated account binding", "Gmail labels exist"}


def test_missing_or_nonprivate_token_blocks_when_requested(tmp_path):
    config = _config(tmp_path)
    missing = build_report(
        config, _confirmation(tmp_path, config), None, "templates", None,
        ACCOUNT, _labels(config), token_path=str(tmp_path / "missing.json"),
    )
    assert missing.ready is False
    assert "token" in " ".join(r.name.lower() for r in missing.blocking)

    token = tmp_path / "token.json"
    token.write_text("{}")
    token.chmod(0o644)
    exposed = build_report(
        config, _confirmation(tmp_path, config), None, "templates", None,
        ACCOUNT, _labels(config), token_path=str(token),
    )
    assert exposed.ready is False
    assert "expected 600" in " ".join(r.detail for r in exposed.blocking)


def test_partial_campaign_readiness_inputs_block(tmp_path):
    config = _config(tmp_path)
    report = build_report(
        config, _confirmation(tmp_path, config), None, "templates", None,
        ACCOUNT, _labels(config), campaign_label="Protected/Campaign",
    )
    assert report.ready is False
    assert "requires" in " ".join(r.detail for r in report.blocking)


# --------------------------------------------------------------------
# Fail-closed: an unknown result is never a pass
# --------------------------------------------------------------------

def test_a_check_that_raises_is_a_failure_not_a_pass():
    def explodes():
        raise RuntimeError("boom")

    result = readiness._guarded("exploding check", explodes)

    assert result.ok is False
    assert "could not complete" in result.detail
    assert "RuntimeError" in result.detail


def test_an_empty_report_is_not_ready():
    """A report with no checks has proven nothing. Returning ready there
    would make a broken check list look like a green light."""
    assert ReadinessReport(account=ACCOUNT).ready is False


def test_a_report_of_only_optional_checks_is_not_ready():
    report = ReadinessReport(account=ACCOUNT)
    report.results.append(CheckResult("advisory", True, "fine", required=False))
    assert report.ready is False


def test_one_failure_among_many_passes_still_blocks():
    report = ReadinessReport(account=ACCOUNT)
    for index in range(6):
        report.results.append(CheckResult(f"ok{index}", True, "fine"))
    report.results.append(CheckResult("bad", False, "unmet"))

    assert report.ready is False
    assert report.status == readiness.NOT_READY
    assert [r.name for r in report.blocking] == ["bad"]


def test_render_names_every_blocking_reason(tmp_path):
    text = _report(tmp_path, account_labels={}).render()
    assert "NOT READY" in text
    assert "Blocking:" in text


# --------------------------------------------------------------------
# Read-only
# --------------------------------------------------------------------

def test_readiness_creates_nothing(tmp_path):
    config = _config(tmp_path)
    before = set(os.listdir(tmp_path))
    _report(tmp_path, config=config)
    created = set(os.listdir(tmp_path)) - before
    assert all(name.startswith("taxonomy-confirmation") for name in created)


def test_readiness_modules_perform_no_writes_and_no_gemini():
    """Static: the checker must not create labels, drafts, or files, and must
    never call the model."""
    import ast
    from pathlib import Path

    for filename in ("readiness.py", "check_readiness.py"):
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {
                    "create", "modify", "trash", "delete", "send",
                    "generate_content", "classify", "generate_reply",
                }, f"{filename} performs a write or model call via {node.func.attr}"

        source = Path(filename).read_text(encoding="utf-8")
        for forbidden in ("gemini_client", "generate_reply"):
            assert forbidden not in source, (
                f"{filename} references {forbidden}; readiness must not call "
                "the model"
            )


# --------------------------------------------------------------------
# The explicit precondition checks must be the ones that fire.
#
# Removing them still blocks - the guarded runner turns the resulting
# TypeError/FileNotFoundError into a failure - so the outcome is safe either
# way. But then the operator is told "check could not complete
# (TypeError...)" instead of what is actually wrong, and the explicit branch
# could be deleted without any test noticing. Pinning the reason makes the
# branch load-bearing.
# --------------------------------------------------------------------

def test_missing_config_reports_the_missing_file_not_an_exception(tmp_path):
    report = _report(tmp_path, config_path=str(tmp_path / "absent.json"))
    detail = next(r.detail for r in report.results if r.name == "account config")

    assert "does not exist" in detail
    assert "could not complete" not in detail, (
        "the explicit existence check was bypassed; the operator is shown a "
        "traceback type instead of the actual problem"
    )


def test_unreadable_labels_report_that_reason_not_an_exception(tmp_path):
    report = _report(tmp_path, account_labels=None)
    detail = next(r.detail for r in report.results
                  if r.name == "Gmail labels exist")

    assert "could not read" in detail
    assert "could not complete" not in detail


def test_no_config_supplied_reports_that_reason(tmp_path):
    report = _report(tmp_path, config_path=None)
    detail = next(r.detail for r in report.results if r.name == "account config")

    assert "no --account-config" in detail
    assert "could not complete" not in detail


# --------------------------------------------------------------------
# CLI network boundary
# --------------------------------------------------------------------

def test_cli_defaults_to_offline_and_never_loads_gmail(tmp_path, monkeypatch):
    config = _config(tmp_path)
    confirmation = _confirmation(tmp_path, config)
    token = tmp_path / "token.json"
    token.write_text("not parsed by an offline check")
    token.chmod(0o600)

    monkeypatch.setattr(
        check_readiness,
        "_read_live_gmail_metadata",
        lambda _path: pytest.fail("offline readiness contacted Gmail"),
    )

    def mark_verification_passed(report):
        report.results.extend((
            CheckResult("full offline test suite", True, "passed"),
            CheckResult("static no-send audit", True, "passed"),
        ))

    monkeypatch.setattr(
        check_readiness, "_append_verification", mark_verification_passed
    )
    result = check_readiness.main([
        "--account-config", config,
        "--taxonomy-confirmation", confirmation,
        "--token-path", str(token),
    ])

    assert result == 0


def test_cli_refuses_broker_contact_without_live(tmp_path, monkeypatch):
    monkeypatch.setattr(
        check_readiness.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("broker was contacted"),
    )
    result = check_readiness.main([
        "--account-config", str(tmp_path / "unused.json"),
        "--taxonomy-confirmation", str(tmp_path / "unused-approval.json"),
        "--broker-health-url", "https://broker.example.test/healthz",
    ])

    assert result == 2


def test_live_service_builder_cannot_start_oauth_or_persist_a_token():
    source = Path("check_readiness.py").read_text(encoding="utf-8")

    assert "InstalledAppFlow" not in source
    assert "get_gmail_service" not in source
    assert "_write_token" not in source
    assert "from_authorized_user_file" in source


# --------------------------------------------------------------------
# The private state directory check had no tests of its own. It fired for
# the first time when a real dry run created triage-state/ at 0755, which
# is also how the nested-parent permissions bug below was found.
# --------------------------------------------------------------------

def _state_dir_result(report):
    return next(result for result in report.results
                if result.name == "private state directory")


def test_a_world_readable_state_directory_blocks(tmp_path):
    config = _config(tmp_path)
    state_dir = tmp_path / "state"
    os.chmod(state_dir, 0o755)
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config))

    assert _state_dir_result(report).ok is False
    assert report.ready is False


def test_a_private_state_directory_passes(tmp_path):
    config = _config(tmp_path)
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config))

    assert _state_dir_result(report).ok is True


def test_an_absent_state_directory_passes_because_it_is_made_privately(tmp_path):
    config = _config(tmp_path)
    (tmp_path / "state").rmdir()
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config))

    result = _state_dir_result(report)
    assert result.ok is True
    assert "will be created privately" in result.detail


def test_a_group_readable_state_directory_blocks(tmp_path):
    """0770 is not private. Checking only the world bits would accept a
    directory readable by every member of the user's group."""
    config = _config(tmp_path)
    os.chmod(tmp_path / "state", 0o770)
    report = _report(tmp_path, config=config,
                     confirmation_path=_confirmation(tmp_path, config))

    assert _state_dir_result(report).ok is False
    assert report.ready is False
