"""Emit a per-account config from an existing single-tenant setup.

One-way read. This never contacts Gmail, never calls Gemini, never modifies an
existing artifact, and never deletes anything. It reads the code-defined
profile plus an optional reviewed label config, and writes one new account
config file for the owner to inspect. Running it twice produces the same
output, so a re-run is harmless.

What carries over untouched, because each is already bound to the account and
keyed independently of this file:

  * the campaign recipient approval artifact
  * template approval artifacts, keyed by template stem
  * the template files themselves, placeholder detection unchanged

What deliberately does NOT carry over:

  * taxonomy confirmation. Every emitted category has no confirmation, so the
    owner confirms fresh even for categories they have used for months.
    Confirmation attests that a human reviewed the taxonomy now; inheriting it
    from history would make "nothing drafts until confirmed" untrue for the
    account most likely to draft first. This is a deliberate cost of about two
    minutes, chosen over a silent exception.
  * drafting modes. Every category is emitted as "off", so migrating cannot
    switch drafting on for anything.

Usage:
    python migrate_account.py --account you@example.edu --output account.json
    python migrate_account.py --account you@example.edu --output account.json \\
        --label-config label-config.example.json --dry-run
"""
import argparse
import json
import os
import sys

import drafting
from account_profile import ACCOUNT_CONFIG_VERSION, load_profile
from taxonomy import proposal_digest, sanitize_slug, validate_label_name


def build_account_config(account, profile=None, label_config=None,
                         timezone=None, paths=None):
    """Build the config document for one account. Pure; writes nothing."""
    profile = profile if profile is not None else load_profile()
    account = (account or "").strip().lower()
    if not account or "@" not in account:
        raise ValueError("migration requires the account's email address")

    label_config = label_config or {}
    configured_categories = label_config.get("categories", {})
    configured_years = label_config.get("years", {})

    taxonomy = []
    for slug in sorted(profile.categories):
        safe_slug = sanitize_slug(slug)
        label = (configured_categories.get(slug)
                 or profile.category_labels.get(slug))
        if label:
            validate_label_name(label)
        description = f"Migrated from the existing {slug} category."
        entry = {
            "slug": safe_slug,
            "display": slug.replace("_", " ").title(),
            "description": description,
            "examples": [],
            # Drafting off for every category. Migration never enables it.
            "drafting": {"mode": drafting.MODE_OFF},
        }
        if label:
            entry["label"] = label
        expected_sender = profile.category_sender_types.get(slug)
        if expected_sender:
            entry["expected_sender"] = expected_sender
        taxonomy.append(entry)

    document = {
        "version": ACCOUNT_CONFIG_VERSION,
        "account": account,
        "timezone": timezone or profile.timezone,
        "taxonomy": taxonomy,
    }

    configured_system = label_config.get("system", {})
    system_labels = configured_system or dict(profile.system_labels)
    if system_labels:
        document["system_labels"] = dict(system_labels)

    protected = sorted(profile.protected_labels)
    if protected:
        document["protected_labels"] = [
            {"label": name, "requires_recipient_approval": True}
            for name in protected
        ]

    evidence = []
    if profile.evidence_categories and profile.evidence_expected_value:
        year_label = configured_years.get(profile.evidence_expected_value)
        for name in protected:
            if year_label in (None, name):
                evidence.append({
                    "label": name,
                    "pattern_set": "grad_year",
                    "classifier_field": "grad_year",
                    "expected_value": profile.evidence_expected_value,
                    "require_sender_type": sorted(profile.evidence_sender_types),
                    "require_categories": sorted(profile.evidence_categories),
                    "min_confidence": "high",
                })
                break
    if evidence:
        document["evidence_gated_labels"] = evidence

    if paths:
        document["paths"] = dict(paths)
    return document


def summarize(document):
    """Human-readable summary of what migration produced."""
    lines = [
        f"Account:            {document['account']}",
        f"Timezone:           {document['timezone']}",
        f"Categories:         {len(document['taxonomy'])}",
        f"Protected labels:   "
        f"{', '.join(entry['label'] for entry in document.get('protected_labels', [])) or 'none'}",
        f"Evidence gates:     {len(document.get('evidence_gated_labels', []))}",
        "",
        "Every category is emitted with drafting mode 'off' and no taxonomy",
        "confirmation. Nothing drafts until you enable a category and confirm",
        "its taxonomy, including categories you have used before.",
        "",
        "Carried over untouched (no re-approval needed):",
        "  - campaign recipient approval artifact",
        "  - template approval artifacts",
        "  - template files, placeholder detection unchanged",
    ]
    return "\n".join(lines)


def write_config(document, output_path):
    """Write the config with owner-only permissions, refusing to overwrite."""
    if os.path.exists(output_path):
        raise FileExistsError(
            f"{output_path} already exists; migration never overwrites an "
            "existing config. Move it aside or choose another path."
        )
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(output_path, 0o600)
    return output_path


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Emit a per-account config from the existing setup. "
                    "Reads only; never contacts Gmail or Gemini."
    )
    parser.add_argument("--account", required=True,
                        help="The Gmail address this config will describe")
    parser.add_argument("--output", required=True,
                        help="Path for the new config (never overwritten)")
    parser.add_argument("--label-config", metavar="FILE",
                        help="Existing reviewed label config to fold in")
    parser.add_argument("--timezone", help="Override the migrated timezone")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the config and summary; write nothing")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    label_config = None
    if args.label_config:
        with open(args.label_config, encoding="utf-8") as handle:
            label_config = json.load(handle)

    document = build_account_config(
        args.account, label_config=label_config, timezone=args.timezone
    )

    print(summarize(document))
    print()

    if args.dry_run:
        print(json.dumps(document, indent=2, sort_keys=True))
        print("\nDry run - nothing written.")
        return 0

    try:
        path = write_config(document, args.output)
    except FileExistsError as exc:
        print(f"Migration error: {exc}")
        return 1
    print(f"Wrote {path} (mode 0600).")
    print("Review it, then confirm each category's taxonomy before enabling "
          "drafting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
