"""Static guard: domain values live in account_profile.py and nowhere else.

Pass one of the multi-inbox generalization collapsed 24 hardcoded sites across
six modules down to one. This test is what keeps them collapsed - without it,
the next edit that reintroduces `"recruit_intro"` or `"YEAR_LABEL"` into a pipeline
module passes silently and the generalization quietly rots back.

The forbidden vocabulary is derived from the profile at test time rather than
retyped here, so it tracks the schema instead of becoming a second list that
drifts. Structural protocol values (confidence levels, sender-type kinds, the
unknown sentinel, the administrative system category) are explicitly exempt:
the code reasons about those, they are not per-inbox choices.

Docstrings are exempt. triage.py documents the approval artifact's shape with
an example address inside a docstring; a documentation example is not a runtime
value. That exemption is a stated decision, not an oversight.
"""
import ast
import re
from pathlib import Path

import pytest

import account_profile
from account_profile import LEGACY_PROFILE

ROOT = Path(__file__).parent

# The module that is allowed to hold domain literals - that is its job.
PROFILE_MODULE = "account_profile.py"

PIPELINE_MODULES = [
    "campaign.py",
    "approve_account.py",
    "broker_client.py",
    "check_readiness.py",
    "readiness.py",
    "broker_crypto.py",
    "broker_wsgi.py",
    "campaign_audit.py",
    "oauth_broker.py",
    "daily_triage.py",
    "discover_taxonomy.py",
    "discovery.py",
    "drafting.py",
    "gemini_client.py",
    "gmail_auth.py",
    "gmail_common.py",
    "gmail_retry.py",
    "gmail_labeler.py",
    "gmail_reader.py",
    "message_safety.py",
    "migrate_account.py",
    "private_runtime.py",
    "local_notifier.py",
    "review_report.py",
    "setup_labels.py",
    "taxonomy.py",
    "triage.py",
    "triage_config.py",
    "triage_limits.py",
    "seat_schedule.py",
    "seats.py",
    "seat_tokens.py",
    "web_status.py",
]

EMAIL_SHAPED = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Protocol values the code reasons about directly. Not per-inbox data.
STRUCTURAL_EXEMPT = (
    set(account_profile.VALID_CONFIDENCE)
    | set(account_profile.VALID_SENDER_TYPES)
    | set(account_profile.SYSTEM_LABEL_KEYS)
    | {account_profile.UNKNOWN,
       account_profile.SYSTEM_CATEGORY_ADMINISTRATIVE}
)


def _forbidden_vocabulary():
    """Domain values that must not appear as literals outside the profile."""
    vocabulary = set(LEGACY_PROFILE.categories)
    vocabulary |= set(LEGACY_PROFILE.protected_labels)
    vocabulary |= set(LEGACY_PROFILE.year_labels.values())
    vocabulary |= set(LEGACY_PROFILE.category_labels.values())
    vocabulary |= set(LEGACY_PROFILE.year_labels)          # "2027" etc.
    vocabulary |= set(LEGACY_PROFILE.supported_years)
    vocabulary |= {LEGACY_PROFILE.timezone}
    return vocabulary - STRUCTURAL_EXEMPT


def _docstring_nodes(tree):
    """Every Constant that is a module/class/function docstring."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    return docstrings


def _string_constants(filename):
    """Yield (lineno, value) for every non-docstring string literal."""
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    skip = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in skip):
            yield node.lineno, node.value


@pytest.mark.parametrize("filename", PIPELINE_MODULES)
def test_no_domain_literals_in_pipeline_modules(filename):
    """H1/H2: category and label names must come from the profile."""
    forbidden = _forbidden_vocabulary()
    offenders = [
        f"{filename}:{lineno}: {value!r}"
        for lineno, value in _string_constants(filename)
        if value in forbidden
    ]
    assert offenders == [], (
        "domain literals must live in account_profile.py:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("filename", PIPELINE_MODULES)
def test_no_account_address_literals_in_pipeline_modules(filename):
    """H3: no email-shaped literal outside a docstring."""
    offenders = [
        f"{filename}:{lineno}: {value!r}"
        for lineno, value in _string_constants(filename)
        if EMAIL_SHAPED.match(value)
    ]
    assert offenders == [], (
        "account addresses must never be literals in pipeline source:\n  "
        + "\n  ".join(offenders)
    )


def test_forbidden_vocabulary_is_non_empty():
    """H4, guard-the-guard: an empty vocabulary would make the checks above
    pass vacuously, exactly the failure mode found in the approval-wiring
    guard this week."""
    vocabulary = _forbidden_vocabulary()

    assert len(vocabulary) >= 15, (
        f"forbidden vocabulary collapsed to {len(vocabulary)} entries; "
        "the literal guards would pass without checking anything"
    )
    # Spot-check that the values that actually matter are in scope.
    for expected in ("YEAR_LABEL", "recruit_intro", "America/New_York"):
        assert expected in vocabulary, (
            f"{expected!r} is no longer guarded against reintroduction"
        )


def test_guard_covers_every_pipeline_module():
    """H5: a guard whose file list can silently shrink guarantees nothing.
    Every production .py except the profile itself must be listed."""
    on_disk = {
        path.name for path in ROOT.glob("*.py")
        if not path.name.startswith(("test_", "demo_", "check_"))
        and path.name not in {PROFILE_MODULE, "classify.py"}
    }
    missing = sorted(on_disk - set(PIPELINE_MODULES))

    assert missing == [], (
        f"production modules absent from the literal guard: {missing}"
    )


def test_profile_module_is_the_one_place_literals_live():
    """The positive half: account_profile.py really does hold the values,
    so the guards above are enforcing a real relocation and not simply
    describing code that deleted the data."""
    text = (ROOT / PROFILE_MODULE).read_text(encoding="utf-8")

    for expected in ("YEAR_LABEL", "recruit_intro", "America/New_York",
                     "Triage/Recruit Intro"):
        assert expected in text, (
            f"{expected!r} is missing from {PROFILE_MODULE}; the profile is "
            "no longer the source of truth"
        )


@pytest.mark.parametrize("filename", PIPELINE_MODULES)
def test_no_domain_value_is_embedded_inside_a_longer_string(filename):
    """The whole-string check above misses a category name buried in prose.

    A dead classification prompt in gemini_client.py carried the entire legacy
    category list inside one 558-character string and was invisible to the
    guard for exactly that reason. Model prompts are the natural place for a
    category vocabulary to reappear, so substrings are checked too.
    """
    forbidden = _forbidden_vocabulary()
    # Years and short tokens appear legitimately inside unrelated prose
    # (a URL, a date, a comment), so only distinctive multi-word or
    # underscored domain values are searched for as substrings.
    distinctive = {
        value for value in forbidden
        if len(value) >= 8 and ("_" in value or "/" in value)
    }
    assert distinctive, "expected distinctive domain values to search for"

    offenders = []
    for lineno, value in _string_constants(filename):
        if len(value) <= 40:
            continue  # already covered by the exact-match test
        for needle in distinctive:
            if needle in value:
                offenders.append(f"{filename}:{lineno}: embeds {needle!r}")
    assert offenders == [], (
        "domain vocabulary embedded in a long string literal:\n  "
        + "\n  ".join(offenders)
    )
