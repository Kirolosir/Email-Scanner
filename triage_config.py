"""Validated, side-effect-free configuration for Gmail triage labels.

The configuration contains the only account-facing label names used by the
daily workflow.  Classifier output is always mapped through these reviewed
keys; model text can therefore never become a Gmail label name.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import account_profile as _PROFILE_MOD
from account_profile import load_profile as _load_profile

_PROFILE = _load_profile()


DEFAULT_LABEL_CONFIG = "label-config.example.json"
SYSTEM_LABEL_KEYS = set(_PROFILE_MOD.SYSTEM_LABEL_KEYS)
CONFIG_CATEGORY_KEYS = set(_PROFILE.categories)


@dataclass(frozen=True)
class TriageLabelConfig:
    years: dict[str, str]
    categories: dict[str, str]
    system: dict[str, str]

    @property
    def creatable_names(self) -> list[str]:
        """Every exact reviewed label the one-time setup may create.

        Creating an evidence-gated label does not apply it to any message; the
        independent evidence gate still controls that later mutation.
        """
        return self.all_names

    @property
    def required_existing_names(self) -> list[str]:
        return []

    @property
    def all_names(self) -> list[str]:
        return sorted(
            set(self.years.values())
            | set(self.categories.values())
            | set(self.system.values())
        )


def _validate_map(document, key):
    value = document.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"label config {key!r} must be an object")
    result = {}
    for source, target in value.items():
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"label config {key!r} keys must be non-empty strings")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"label config {key!r} values must be non-empty strings")
        result[source.strip()] = target.strip()
    return result


def load_triage_label_config(path=None, profile=None):
    """Load reviewed label names without making any network request.

    A per-account profile is the primary source for generalized accounts. A
    separate label config may still be supplied as an explicit override. The
    legacy invocation continues to read ``label-config.example.json``.
    """
    profile = profile if profile is not None else _PROFILE
    generalized = bool(getattr(profile, "taxonomy", ()))
    source_path = path or (None if generalized else DEFAULT_LABEL_CONFIG)
    if source_path:
        with Path(source_path).open(encoding="utf-8") as config_file:
            document = json.load(config_file)
    else:
        document = {
            "years": dict(profile.year_labels),
            "categories": dict(profile.category_labels),
            "system": dict(profile.system_labels),
        }
    if not isinstance(document, dict):
        raise ValueError("label config must be a JSON object")

    years = _validate_map(document, "years")
    categories = _validate_map(document, "categories")
    system = _validate_map(document, "system")

    unexpected_system = set(system) - SYSTEM_LABEL_KEYS
    if unexpected_system:
        raise ValueError(
            "unsupported system label keys: "
            + ", ".join(sorted(unexpected_system))
        )
    expected_categories = (
        set(profile.categories) if generalized else CONFIG_CATEGORY_KEYS
    )
    if not generalized:
        reviewed_year, reviewed_label = _PROFILE_MOD.LEGACY_REVIEWED_YEAR_LABEL
        if years.get(reviewed_year) != reviewed_label:
            raise ValueError(
                f"the reviewed {reviewed_year} year label must be exactly "
                f"{reviewed_label!r}"
            )
    else:
        expected_years = dict(profile.year_labels)
        if years != expected_years:
            raise ValueError(
                "year label configuration must exactly match the account "
                "profile's reviewed evidence gates"
            )
    if set(categories) != expected_categories:
        missing = sorted(expected_categories - set(categories))
        unexpected = sorted(set(categories) - expected_categories)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unsupported " + ", ".join(unexpected))
        raise ValueError("category label configuration is incomplete: " + "; ".join(details))
    if set(system) != SYSTEM_LABEL_KEYS:
        missing = SYSTEM_LABEL_KEYS - set(system)
        raise ValueError(
            "label config must define system labels: "
            + ", ".join(sorted(missing))
        )

    if generalized and system != dict(profile.system_labels):
        raise ValueError(
            "system label configuration must exactly match the account profile"
        )

    all_names = list(years.values()) + list(categories.values()) + list(system.values())
    duplicates = sorted({name for name in all_names if all_names.count(name) > 1})
    if duplicates:
        raise ValueError(
            "each configured semantic label must have a distinct Gmail name; "
            f"duplicates: {', '.join(duplicates)}"
        )

    return TriageLabelConfig(years, categories, system)
