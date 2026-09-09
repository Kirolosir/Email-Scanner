"""Create private taxonomy and AI-drafting approvals after one human review.

This is an offline setup helper. It never imports Gmail or Gemini modules,
never changes the account config, and refuses to overwrite an existing
artifact. It replaces error-prone hand-written JSON/heredocs with one exact,
account-bound confirmation step.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from account_profile import load_profile
from drafting import (
    AI_DRAFTING_ACKNOWLEDGEMENT,
    GLOBAL_DRAFTING_ACKNOWLEDGEMENT,
    GLOBAL_DRAFTING_APPROVAL_VERSION,
    MODE_GENERIC,
    drafting_policy_digest,
)


def confirmation_phrase(profile, generic_categories,
                        allow_protected_labels=False,
                        global_policy=False):
    """The exact sentence the account owner must type.

    allow_protected_labels is part of the sentence, not just a flag. It is a
    strictly larger grant - permission for model-written text on messages
    carrying a protected label - and a confirmation that reads identically
    whether or not it was given is not a confirmation of it. Passing the flag
    alone must never be enough.

    The sentence states the scope the code actually implements. It must never
    promise more than that: a confirmation broader than the behavior would
    pre-authorize a later loosening of the delivery-header policy, and the
    owner would never be asked again.
    """
    if global_policy:
        phrase = (
            f"I reviewed {len(profile.taxonomy)} categories for {profile.account} "
            "and activate unsent AI drafts for every message with a safe "
            "reply address outside Spam, Trash, Sent, and Drafts"
        )
    else:
        phrase = (
            f"I reviewed {len(profile.taxonomy)} categories for {profile.account} "
            f"and approve unsent AI drafts for {len(generic_categories)} categories"
        )
    if allow_protected_labels:
        phrase += ", including messages under protected labels"
    return phrase


def build_documents(profile, allow_protected_labels=False):
    """Build approval documents from the exact loaded account profile."""
    if not profile.account or not profile.taxonomy:
        raise ValueError("a bound per-account taxonomy config is required")
    taxonomy_document = {
        "version": 1,
        "account": profile.account,
        "confirmed_categories": {
            entry["slug"]: entry["digest"] for entry in profile.taxonomy
        },
    }
    generic = sorted(
        slug for slug, mode in profile.drafting_modes.items()
        if mode == MODE_GENERIC
    )
    ai_document = None
    if getattr(profile, "draft_all_replyable_messages", False):
        ai_document = {
            "version": GLOBAL_DRAFTING_APPROVAL_VERSION,
            "account": profile.account,
            "draft_all_replyable_messages": True,
            "policy_digest": drafting_policy_digest(
                profile, allow_protected_labels
            ),
            "allow_protected_labels": bool(allow_protected_labels),
            "acknowledgement": GLOBAL_DRAFTING_ACKNOWLEDGEMENT,
        }
    elif generic:
        ai_document = {
            "version": 1,
            "account": profile.account,
            "approved_categories": generic,
            "allow_protected_labels": bool(allow_protected_labels),
            "acknowledgement": AI_DRAFTING_ACKNOWLEDGEMENT,
        }
    return taxonomy_document, ai_document


def _write_private_json(path, document):
    parent = os.path.dirname(path)
    if parent:
        created = not os.path.isdir(parent)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if created:
            # Only tighten a directory this tool made. chmod on a shared
            # parent the user does not own (/tmp, a group directory) raises
            # EPERM and would abort an otherwise safe write. The file itself
            # is created 0600 regardless, which is the property that matters.
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def write_documents(taxonomy_path, taxonomy_document, ai_path=None,
                    ai_document=None):
    """Write both or neither when an output already exists."""
    targets = [taxonomy_path]
    if ai_document is not None:
        if not ai_path:
            raise ValueError(
                "--ai-output is required because generic drafting is enabled"
            )
        targets.append(ai_path)
    existing = [path for path in targets if os.path.exists(path)]
    if existing:
        raise FileExistsError(
            "approval builder never overwrites existing files: "
            + ", ".join(existing)
        )
    written = []
    try:
        _write_private_json(taxonomy_path, taxonomy_document)
        written.append(taxonomy_path)
        if ai_document is not None:
            _write_private_json(ai_path, ai_document)
            written.append(ai_path)
    except Exception:
        for path in written:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    return written


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Review one account taxonomy and create private, account-bound "
            "taxonomy/AI-drafting approval files. Makes zero network calls."
        )
    )
    parser.add_argument("--account-config", required=True)
    parser.add_argument("--taxonomy-output", required=True)
    parser.add_argument("--ai-output")
    parser.add_argument(
        "--allow-protected-labels", action="store_true",
        help=("Allow AI drafts for approved messages that already carry or "
              "will receive a protected label"),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show exactly what would be approved; write nothing",
    )
    return parser.parse_args(argv)


def main(argv=None, reader=input):
    args = parse_args(argv)
    try:
        profile = load_profile(args.account_config)
        taxonomy_document, ai_document = build_documents(
            profile, allow_protected_labels=args.allow_protected_labels
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Account approval error: {exc}")
        return 2

    global_policy = bool(
        (ai_document or {}).get("draft_all_replyable_messages", False)
    )
    generic = sorted((ai_document or {}).get("approved_categories", ()))
    print(f"Account: {profile.account}")
    print(f"Taxonomy categories ({len(profile.taxonomy)}):")
    for entry in profile.taxonomy:
        mode = profile.drafting_modes.get(entry["slug"], "off")
        print(
            f"  {entry['slug']}: {entry.get('label') or '(no label)'} "
            f"[drafting={mode}]"
        )
        if entry.get("description"):
            print(f"    {entry['description']}")
    if global_policy:
        print("AI-generated drafts: all replyable messages")
        print(f"Fallback category: {profile.fallback_category}")
    else:
        print(f"AI-generated draft categories: {', '.join(generic) or 'none'}")
    print(
        "Protected-label AI drafting: "
        + ("approved" if args.allow_protected_labels else "blocked")
    )

    if args.dry_run:
        print("\nDry run - no approval files written and no network calls made.")
        return 0

    phrase = confirmation_phrase(
        profile, generic, allow_protected_labels=args.allow_protected_labels,
        global_policy=global_policy,
    )
    print("\nTo create the private approval files, type this line exactly:")
    print(f"  {phrase}")
    try:
        typed = reader("> ")
    except EOFError:
        print("No interactive input available; nothing written.")
        return 1
    if typed.strip() != phrase:
        print("Confirmation did not match; nothing written.")
        return 1

    try:
        written = write_documents(
            args.taxonomy_output, taxonomy_document,
            args.ai_output, ai_document,
        )
    except (OSError, ValueError) as exc:
        print(f"Account approval error: {exc}")
        return 2
    for path in written:
        print(f"Wrote {path} (mode 0600).")
    print("No Gmail or Gemini call was made.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
