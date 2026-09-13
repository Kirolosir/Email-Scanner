"""Static guards that every approval binding is wired to runtime values.

Both approval systems - the campaign recipient allowlist and the per-template
approval - validate correctly when called correctly. Their unit tests prove
that. What no unit test could see is the *call site*: an approval check that
is handed a hardcoded literal still passes every functional test while binding
to nothing real.

That gap was found by mutation testing the template-approval guard, which
originally only counted arguments and so accepted a hardcoded account. The
same mutations were then run against the campaign approval call site, where
all three passed undetected because no static guard existed at all:

  * account replaced with a literal  -> approval validates against the literal
    instead of the authenticated mailbox
  * label replaced with a literal    -> approval accepted for the wrong label
  * path replaced with None          -> load returns None, select_targets
    treats None as "no allowlist", and every deduped sender becomes eligible
    while the run still reports as approved

These are all silent-widening failures, so they are asserted statically here.
"""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).parent

# function name -> {positional index: what that argument secures}
# Every listed argument must come from runtime state, never a literal.
APPROVAL_BINDINGS = {
    "load_campaign_approval": {
        0: ("approval file path", "a literal None disables recipient "
            "filtering entirely while the run still reports as approved"),
        1: ("campaign label", "a literal would accept an approval reviewed "
            "for a different label"),
        2: ("authenticated Gmail account", "a literal would bind the approval "
            "to a hardcoded address instead of the real mailbox"),
    },
    "build_template_approvals": {
        0: ("approval file path", "a literal would ignore --template-approval"),
        2: ("authenticated Gmail account", "a literal would bind the approval "
            "to a hardcoded address instead of the real mailbox"),
    },
    "load_ai_drafting_approval": {
        0: ("drafting approval file path", "a literal would ignore the "
            "operator-selected approval artifact"),
        1: ("authenticated Gmail account", "a literal would bind drafting "
            "to a hardcoded mailbox"),
        2: ("runtime taxonomy", "a literal would approve categories outside "
            "the account configuration"),
        3: ("runtime account profile", "a literal or omitted profile would "
            "leave a global approval unbound from its configuration digest"),
    },
}

# Arguments that may legitimately be omitted, but must still be runtime values
# when supplied. build_template_approvals' label is optional because
# daily_triage.py scans an inbox query rather than one label - but triage.py
# does pass it, and a literal there would accept an approval scoped to a
# different label.
OPTIONAL_BINDINGS = {
    "build_template_approvals": {
        3: ("triage label", "a literal would accept an approval scoped to a "
            "different label than the one being triaged"),
    },
}
OPTIONAL_PARAMETER_NAMES = {
    "build_template_approvals": {3: "label_name"},
}

# Parameter names, for call sites that pass these by keyword instead.
PARAMETER_NAMES = {
    "load_campaign_approval": {0: "path", 1: "label_name", 2: "actual_account"},
    "build_template_approvals": {
        0: "approval_path", 2: "actual_account",
    },
    "load_ai_drafting_approval": {
        0: "path", 1: "actual_account", 2: "valid_categories", 3: "profile",
    },
}

PRODUCTION_FILES = [
    "campaign.py", "triage.py", "daily_triage.py", "readiness.py",
]

# Arguments that must never acquire a default value at the definition site.
# A default of "" or None would let a caller omit the binding silently.
REQUIRED_PARAMETERS = {
    "load_campaign_approval": ["path", "label_name", "actual_account"],
    "build_template_approvals": ["approval_path", "approved_names",
                                 "actual_account"],
    "load_template_approval": ["path", "actual_account"],
    "load_ai_drafting_approval": [
        "path", "actual_account", "valid_categories",
    ],
}


def _alias_map(tree):
    """Local name -> imported name, for `from x import y as z`.

    Without this, a module that imports an approval loader under an alias is
    invisible to every check below. triage.py does exactly that
    (`load_ai_drafting_approval as _load_ai_drafting_approval`), so its drafting
    drafting binding was silently unguarded: a hardcoded account there would
    have passed the whole suite. A guard that can be evaded by renaming an
    import is not a guard.
    """
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
    return aliases


def _calls_to(tree, name, aliases=None):
    aliases = aliases if aliases is not None else _alias_map(tree)
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (
                isinstance(node.func, ast.Name)
                and aliases.get(node.func.id, node.func.id) == name
            )
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == name
            )
        )
    ]


def _argument_at(call, index, parameter_name):
    if len(call.args) > index:
        return call.args[index]
    return next(
        (kw.value for kw in call.keywords if kw.arg == parameter_name), None
    )


def _iter_binding_calls():
    for filename in PRODUCTION_FILES:
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        aliases = _alias_map(tree)
        for function, spec in APPROVAL_BINDINGS.items():
            for call in _calls_to(tree, function, aliases):
                yield filename, function, spec, call


def test_every_approval_binding_argument_is_a_runtime_value():
    """The guard the campaign check never had: no literal may stand in for
    the path, label, or authenticated account at any approval call site."""
    checked = 0
    for filename, function, spec, call in _iter_binding_calls():
        for index, (what, consequence) in spec.items():
            argument = _argument_at(
                call, index, PARAMETER_NAMES[function][index]
            )
            assert argument is not None, (
                f"{filename}:{call.lineno} calls {function} without supplying "
                f"the {what}; {consequence}"
            )
            assert not isinstance(argument, ast.Constant), (
                f"{filename}:{call.lineno} passes a literal as the {what} to "
                f"{function}; {consequence}"
            )
            assert isinstance(argument, (ast.Name, ast.Attribute, ast.Call)), (
                f"{filename}:{call.lineno} passes a non-runtime expression as "
                f"the {what} to {function}"
            )
            checked += 1
    assert checked, "expected to find approval binding call sites to check"


def test_optional_binding_arguments_are_runtime_values_when_supplied():
    """An optional binding argument may be omitted, but supplying a literal
    is never legitimate - it would silently accept a mismatched scope."""
    for filename, function, _spec, call in _iter_binding_calls():
        for index, (what, consequence) in OPTIONAL_BINDINGS.get(
            function, {}
        ).items():
            argument = _argument_at(
                call, index, OPTIONAL_PARAMETER_NAMES[function][index]
            )
            if argument is None:
                continue  # legitimately omitted
            assert not isinstance(argument, ast.Constant), (
                f"{filename}:{call.lineno} passes a literal as the {what} to "
                f"{function}; {consequence}"
            )
            assert isinstance(argument, (ast.Name, ast.Attribute, ast.Call)), (
                f"{filename}:{call.lineno} passes a non-runtime expression as "
                f"the {what} to {function}"
            )


def test_both_approval_systems_are_actually_wired():
    """Guards the guard: if a call site is deleted or renamed, the loop above
    would vacuously pass. Assert both systems are present."""
    found = {function: 0 for function in APPROVAL_BINDINGS}
    for _filename, function, _spec, _call in _iter_binding_calls():
        found[function] += 1

    assert found["load_campaign_approval"] >= 1, (
        "campaign.py no longer calls load_campaign_approval"
    )
    assert found["build_template_approvals"] >= 2, (
        "expected both triage.py and daily_triage.py to bind template approvals"
    )
    assert found["load_ai_drafting_approval"] >= 2, (
        "expected both triage.py and daily_triage.py to bind drafting approval"
    )


@pytest.mark.parametrize("function,parameters", sorted(REQUIRED_PARAMETERS.items()))
def test_binding_parameters_have_no_defaults(function, parameters):
    """A default on a security argument lets a caller omit it silently."""
    for filename in ("campaign.py", "triage.py", "drafting.py"):
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        definitions = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == function
        ]
        for definition in definitions:
            positional = definition.args.args
            defaults = definition.args.defaults
            # defaults align to the tail of the positional list
            defaulted = {
                argument.arg
                for argument in positional[len(positional) - len(defaults):]
            }
            for parameter in parameters:
                assert parameter not in defaulted, (
                    f"{filename}: {function}() gives {parameter!r} a default; "
                    "it must stay required so the binding cannot be skipped"
                )


def test_guard_resolves_aliased_imports():
    """Guards the guard. triage.py imports the drafting loader under an
    alias; before alias resolution the guard counted zero calls there and
    skipped every argument check, so a hardcoded account in triage.py would
    have passed silently."""
    tree = ast.parse(
        "from drafting import load_ai_drafting_approval as _loader\n"
        "x = _loader(path, account, taxonomy)\n"
    )
    calls = _calls_to(tree, "load_ai_drafting_approval")

    assert len(calls) == 1, (
        "the guard cannot see a call made through an aliased import"
    )


def test_every_production_file_binding_is_actually_inspected():
    """Each production file that imports an approval loader must contribute
    at least one inspected call, or its binding is unguarded."""
    seen = {}
    for filename, function, _spec, _call in _iter_binding_calls():
        seen.setdefault(filename, set()).add(function)

    assert "load_ai_drafting_approval" in seen.get("triage.py", set()), (
        "triage.py's drafting binding is not being inspected"
    )
    assert "load_ai_drafting_approval" in seen.get("daily_triage.py", set()), (
        "daily_triage.py's drafting binding is not being inspected"
    )
    assert "load_ai_drafting_approval" in seen.get("readiness.py", set()), (
        "readiness.py's drafting binding is not being inspected"
    )
