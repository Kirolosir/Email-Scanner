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
        """Exact triage labels setup may create (year labels are existing-only)."""
        return sorted(set(self.categories.values()) | set(self.system.values()))

    @property
    def required_existing_names(self) -> list[str]:
        return sorted(set(self.years.values()))

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


def load_triage_label_config(path=DEFAULT_LABEL_CONFIG):
    """Load reviewed label names without making any network request."""
    with Path(path).open(encoding="utf-8") as config_file:
        document = json.load(config_file)
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
    reviewed_year, reviewed_label = _PROFILE_MOD.LEGACY_REVIEWED_YEAR_LABEL
    if years.get(reviewed_year) != reviewed_label:
        raise ValueError(
            f"the reviewed {reviewed_year} year label must be exactly "
            f"{reviewed_label!r}"
        )
    if set(categories) != CONFIG_CATEGORY_KEYS:
        missing = sorted(CONFIG_CATEGORY_KEYS - set(categories))
        unexpected = sorted(set(categories) - CONFIG_CATEGORY_KEYS)
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

    all_names = list(years.values()) + list(categories.values()) + list(system.values())
    duplicates = sorted({name for name in all_names if all_names.count(name) > 1})
    if duplicates:
        raise ValueError(
            "each configured semantic label must have a distinct Gmail name; "
            f"duplicates: {', '.join(duplicates)}"
        )

    return TriageLabelConfig(years, categories, system)
