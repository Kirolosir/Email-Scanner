"""Offline tests for the per-account CLI surface and the migration tool.

Two properties under test:

  * The new CLI flags are optional and default to the pre-generalization
    behavior, so an existing invocation keeps working and the prepared
    launchd plist does not need editing.
  * Migration is a one-way read that never grants anything. In particular it
    never emits a taxonomy confirmation and never enables drafting, so an
    account that has used its categories for months still confirms fresh.
"""
import json
import os

import pytest

import campaign
import daily_triage
import drafting
import migrate_account
import triage
from account_profile import (
    LEGACY_PROFILE,
    assert_profile_matches_account,
    load_profile,
)
from migrate_account import build_account_config, summarize, write_config

ACCOUNT = "coach@example.test"


# --------------------------------------------------------------------
# CLI surface: additive and defaulted
# --------------------------------------------------------------------

@pytest.mark.parametrize("module,argv", [
    (triage, ["INBOX"]),
    (daily_triage, ["daily"]),
])
def test_new_flags_default_to_legacy_behavior(module, argv):
    """Existing invocations keep working; nothing is newly required."""
    args = module.parse_args(argv)

    assert args.account_config is None
    assert args.taxonomy_confirmation is None
    assert load_profile(args.account_config) is LEGACY_PROFILE


def test_launchd_plist_invocation_still_parses():
    """The prepared 6PM schedule must not need editing to keep working."""
    args = daily_triage.parse_args([
        "daily", "--apply", "--yes", "--scheduled",
        "--token-path", "tokens/coach.json",
        "--max-scan", "25", "--limit", "25", "--max-drafts", "5",
    ])

    assert args.apply is True and args.yes is True and args.scheduled is True
    assert args.account_config is None


def test_campaign_cli_is_unchanged():
    """Migration and per-account config do not touch the campaign CLI."""
    args = campaign.parse_args(["YEAR_LABEL", "body.txt", "--limit", "3"])
    assert args.label == "YEAR_LABEL" and args.limit == 3


# --------------------------------------------------------------------
# Account binding on the config itself
# --------------------------------------------------------------------

def _profile(tmp_path, account=ACCOUNT):
    document = {
        "version": 1, "account": account, "timezone": "UTC",
        "taxonomy": [{"slug": "recruiting", "label": "Triage/Recruiting"}],
    }
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))
    return load_profile(str(path))


def test_account_config_is_bound_to_the_authenticated_mailbox(tmp_path):
    profile = _profile(tmp_path)

    assert assert_profile_matches_account(profile, ACCOUNT) is profile
    assert assert_profile_matches_account(profile, "Coach@Example.TEST")

    with pytest.raises(ValueError, match="different Gmail account"):
        assert_profile_matches_account(profile, "someone@else.test")


def test_legacy_profile_is_exempt_from_the_account_binding():
    """The code-defined default declares no account; it is the
    pre-migration state, not a per-account artifact."""
    assert assert_profile_matches_account(LEGACY_PROFILE, "anyone@example.test")


# --------------------------------------------------------------------
# Migration: never grants, never overwrites, never contacts anything
# --------------------------------------------------------------------

def test_migration_reproduces_the_existing_setup():
    document = build_account_config(ACCOUNT)

    assert document["account"] == ACCOUNT
    assert document["timezone"] == LEGACY_PROFILE.timezone
    slugs = {entry["slug"] for entry in document["taxonomy"]}
    assert slugs == set(LEGACY_PROFILE.categories)
    assert [entry["label"] for entry in document["protected_labels"]] == ["YEAR_LABEL"]
    assert document["evidence_gated_labels"][0]["expected_value"] == "2027"


def test_migration_never_emits_a_taxonomy_confirmation():
    """The decision you overrode me on: an existing account confirms fresh."""
    document = build_account_config(ACCOUNT)

    serialized = json.dumps(document)
    assert "confirmation" not in serialized, (
        "migration emitted a confirmation; every category must be confirmed "
        "fresh by the owner"
    )
    for entry in document["taxonomy"]:
        assert "confirmation" not in entry


def test_migration_leaves_drafting_off_for_every_category():
    document = build_account_config(ACCOUNT)

    modes = {entry["slug"]: entry["drafting"]["mode"]
             for entry in document["taxonomy"]}
    assert set(modes.values()) == {drafting.MODE_OFF}, (
        f"migration enabled drafting for {sorted(modes)}"
    )


def test_migrated_config_loads_and_drafts_nothing(tmp_path):
    """End to end: the emitted config is valid, and produces a profile in
    which every category is off and unconfirmed."""
    document = build_account_config(ACCOUNT)
    path = tmp_path / "migrated.json"
    path.write_text(json.dumps(document))

    profile = load_profile(str(path))

    assert profile.account == ACCOUNT
    assert set(profile.drafting_modes.values()) == {drafting.MODE_OFF}
    for slug in profile.categories:
        assert drafting.resolve_mode(profile, slug) == drafting.MODE_OFF


def test_migration_is_idempotent():
    assert build_account_config(ACCOUNT) == build_account_config(ACCOUNT)


def test_migration_requires_a_real_account_address():
    for bad in ("", "   ", "not-an-address", None):
        with pytest.raises(ValueError, match="email address"):
            build_account_config(bad)


def test_migration_refuses_to_overwrite_an_existing_config(tmp_path):
    """Never destroys review work already recorded in a config."""
    path = tmp_path / "account.json"
    path.write_text('{"existing": true}')

    with pytest.raises(FileExistsError, match="never overwrites"):
        write_config(build_account_config(ACCOUNT), str(path))

    assert json.loads(path.read_text()) == {"existing": True}


def test_written_config_is_owner_only(tmp_path):
    path = str(tmp_path / "nested" / "account.json")
    write_config(build_account_config(ACCOUNT), path)

    assert oct(os.stat(path).st_mode)[-3:] == "600"
    assert oct(os.stat(os.path.dirname(path)).st_mode)[-3:] == "700"


def test_migration_folds_in_a_reviewed_label_config():
    label_config = {
        "years": {"2027": "YEAR_LABEL"},
        "categories": {"parent": "Example/Triage/Parent"},
        "system": {"needs_review": "Example/Triage/Needs Review",
                   "processed": "Example/Triage/Processed"},
    }
    document = build_account_config(ACCOUNT, label_config=label_config)

    parent = next(e for e in document["taxonomy"] if e["slug"] == "parent")
    assert parent["label"] == "Example/Triage/Parent"


def test_migration_refuses_an_unsafe_label_from_a_label_config():
    """A label config naming a reserved Gmail label must not migrate."""
    from taxonomy import TaxonomyError

    with pytest.raises(TaxonomyError):
        build_account_config(
            ACCOUNT, label_config={"categories": {"parent": "INBOX"}}
        )


def test_summary_states_what_did_not_carry_over():
    """The owner must be told confirmation did not transfer, or they will
    assume their existing review still counts."""
    text = summarize(build_account_config(ACCOUNT))

    assert "drafting mode 'off'" in text
    assert "no taxonomy" in text and "confirmation" in text
    assert "categories you have used before" in text


def test_migration_module_never_touches_gmail_or_gemini():
    """Static check: migration is a read of local state only."""
    import ast
    from pathlib import Path

    source = Path("migrate_account.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    for forbidden in ("gmail_auth", "gmail_common", "gmail_reader",
                      "gmail_labeler", "gemini_client", "googleapiclient"):
        assert forbidden not in imported, (
            f"migrate_account.py imports {forbidden}; migration must not "
            "contact Gmail or Gemini"
        )


# --------------------------------------------------------------------
# Gaps found by mutation testing this pass, closed here.
# --------------------------------------------------------------------

def _plan_message_calls(filename):
    import ast
    from pathlib import Path
    tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "plan_message"
    ]


@pytest.mark.parametrize("filename", ["triage.py", "daily_triage.py"])
def test_pipelines_forward_every_gate_into_plan_message(filename):
    """M8/M9. Each gate is enforced inside plan_message, so a call site that
    drops one silently disables it for that pipeline. parse_args tests cannot
    see this - only the call site can."""
    required = {
        "template_approvals", "taxonomy_confirmation", "profile",
        "ai_drafting_approvals",
    }
    calls = _plan_message_calls(filename)

    assert calls, f"expected {filename} to call plan_message"
    for call in calls:
        supplied = {kw.arg for kw in call.keywords}
        missing = sorted(required - supplied)
        assert not missing, (
            f"{filename}:{call.lineno} calls plan_message without {missing}; "
            "those gates would be silently disabled for this pipeline"
        )


@pytest.mark.parametrize("filename", ["triage.py", "daily_triage.py"])
def test_pipelines_pass_runtime_values_not_literals_into_plan_message(filename):
    """A hardcoded confirmation or profile would satisfy the guard above
    while binding to nothing real - the failure mode found in the approval
    wiring earlier."""
    import ast
    for call in _plan_message_calls(filename):
        for keyword in call.keywords:
            if keyword.arg in {
                "taxonomy_confirmation", "profile", "ai_drafting_approvals",
            }:
                assert not isinstance(keyword.value, ast.Constant), (
                    f"{filename}:{call.lineno} passes a literal as "
                    f"{keyword.arg}"
                )


def test_write_config_uses_an_exclusive_create():
    """M6. The exists() check alone is a TOCTOU race; O_EXCL is what makes
    the refusal atomic, and its absence is invisible at runtime because a
    later chmod still lands the file at 0600."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("migrate_account.py").read_text(encoding="utf-8"))
    flags = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"):
            flags.append(ast.unparse(node))

    assert flags, "expected migrate_account to open the config explicitly"
    assert any("O_EXCL" in flag for flag in flags), (
        "config creation must use O_EXCL so an existing file cannot be "
        "clobbered between the check and the write"
    )
    # ast.unparse renders 0o600 as its decimal value, 384.
    assert any(("0o600" in flag or "384" in flag) for flag in flags), (
        "config must be created owner-only, not merely chmod'd afterwards"
    )


def test_account_config_loads_dynamic_year_gate_system_labels_and_ai_guidance(
    tmp_path,
):
    document = {
        "version": 1,
        "account": ACCOUNT,
        "timezone": "America/New_York",
        "taxonomy": [
            {
                "slug": "prospect",
                "display": "Prospect",
                "description": "A prospective applicant.",
                "examples": ["Class of 2027"],
                "label": "Custom/Prospect",
                "expected_sender": "recruit",
                "drafting": {
                    "mode": "generic",
                    "guidance": "Acknowledge without making a promise.",
                },
            },
            {
                "slug": "other",
                "display": "Other",
                "description": "Other human mail.",
                "examples": [],
                "label": "Custom/Other",
                "drafting": {"mode": "off"},
            },
        ],
        "protected_labels": [{"label": "Prospects/2027"}],
        "evidence_gated_labels": [{
            "label": "Prospects/2027",
            "pattern_set": "grad_year",
            "classifier_field": "grad_year",
            "expected_value": "2027",
            "require_sender_type": ["recruit"],
            "require_categories": ["prospect"],
            "min_confidence": "high",
        }],
        "system_labels": {
            "needs_review": "Custom/Needs Review",
            "processed": "Custom/Processed",
        },
        "ai_drafting": {
            "display_name": "Coach Example",
            "signature": "Coach Example",
            "default_guidance": "Use only known facts.",
            "max_words": 120,
        },
    }
    path = tmp_path / "account.json"
    path.write_text(json.dumps(document))

    profile = load_profile(str(path))

    assert profile.year_labels == {"2027": "Prospects/2027"}
    assert profile.supported_years == {"2027"}
    assert profile.evidence_categories == {"prospect"}
    assert profile.evidence_sender_types == {"recruit"}
    assert profile.system_labels["processed"] == "Custom/Processed"
    assert profile.drafting_guidance["prospect"].startswith("Acknowledge")
    assert profile.ai_drafting["max_words"] == 120


def test_migration_carries_reviewed_system_labels_into_account_config():
    label_config = {
        "years": {"2027": "YEAR_LABEL"},
        "categories": dict(LEGACY_PROFILE.category_labels),
        "system": {
            "needs_review": "Custom/Needs Review",
            "processed": "Custom/Processed",
        },
    }
    document = build_account_config(ACCOUNT, label_config=label_config)
    assert document["system_labels"] == label_config["system"]


# --------------------------------------------------------------------
# The prepared account config must stay prepared, not activated.
# --------------------------------------------------------------------

PREPARED_CONFIG = "account-config.prepared.json"


def test_prepared_config_exists_and_loads():
    """Drafted wording guidance belongs in the repository where it can be
    reviewed, not only in a chat transcript."""
    from account_profile import load_profile

    profile = load_profile(PREPARED_CONFIG)
    assert profile.account == "owner@example.edu"
    assert len(profile.taxonomy) == 8


def test_prepared_config_activates_nothing():
    """It is inert by construction: no approval artifact is bound to it, and
    it declares no protected label, so no drafting can occur from it alone."""
    import os
    from account_profile import load_profile

    profile = load_profile(PREPARED_CONFIG)

    # No confirmation or approval may be embedded in the config itself.
    # Checked structurally, not by substring: the explanatory _comment
    # legitimately uses the word "confirmation" to say one is REQUIRED, and a
    # blob-wide search would flag the very text that documents the blocker.
    document = json.load(open(PREPARED_CONFIG))
    payload = {k: v for k, v in document.items() if k != "_comment"}
    assert "confirmation" not in json.dumps(payload)
    assert "approved_categories" not in payload
    assert "unreviewed_bulk_acknowledgement" not in payload
    for entry in payload["taxonomy"]:
        assert "confirmation" not in entry
        assert "digest" not in entry

    # No protected label, so the higher-consequence grant is not in play.
    assert profile.protected_labels == frozenset()

    # And no approval artifact exists on disk for this account.
    for sibling in ("accounts/owner-taxonomy.json", "accounts/owner-ai.json"):
        assert not os.path.exists(sibling), (
            f"{sibling} exists; the prepared config is no longer inert"
        )


def test_prepared_config_states_the_blockers():
    """Anyone opening the file must learn it needs institutional approval for Gmail
    AND, separately, for sending recruit content to Gemini."""
    document = json.load(open(PREPARED_CONFIG))
    comment = document["_comment"]

    assert "NOT ACTIVATED" in comment
    assert "admin_policy_enforced" in comment
    assert "Gemini" in comment and "SEPARATE" in comment
    assert "approve_account.py" in comment


def test_prepared_config_other_category_is_off():
    """'other' routes to Needs Review rather than drafting."""
    from account_profile import load_profile
    import drafting

    profile = load_profile(PREPARED_CONFIG)
    assert profile.drafting_modes["other"] == drafting.MODE_OFF
