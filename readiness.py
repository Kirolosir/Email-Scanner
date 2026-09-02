"""Pure, fail-closed readiness checks for one configured Gmail account.

The library performs no network calls and creates no files. The CLI composes
these checks in two stages: local checks are the default, while ``--live``
adds read-only Gmail identity/label checks. A check that cannot complete is
always a failure; an unknown result is never rounded up to ready.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field

import drafting
import triage
from account_profile import assert_profile_matches_account, load_profile
from taxonomy import load_taxonomy_confirmation

READY = "ready"
NOT_READY = "not ready"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    required: bool = True


@dataclass
class ReadinessReport:
    account: str = ""
    live: bool = True
    results: list = field(default_factory=list)

    @property
    def blocking(self):
        return [result for result in self.results
                if result.required and not result.ok]

    @property
    def ready(self):
        required = [result for result in self.results if result.required]
        return bool(required) and not self.blocking

    @property
    def status(self):
        return READY if self.ready else NOT_READY

    def render(self):
        scope = "LIVE READ-ONLY" if self.live else "OFFLINE"
        lines = [f"Account: {self.account or '(unknown)'}",
                 f"Scope: {scope}", ""]
        for result in self.results:
            mark = "PASS" if result.ok else (
                "FAIL" if result.required else "SKIP"
            )
            lines.append(f"  [{mark}] {result.name}: {result.detail}")
        lines.append("")
        final = "READY" if self.ready else "NOT READY"
        if self.ready and not self.live:
            final = "OFFLINE READY (live Gmail checks not performed)"
        lines.append(f"Status: {final}")
        if self.blocking:
            lines.extend(("", "Blocking:"))
            for result in self.blocking:
                lines.append(f"  - {result.name}: {result.detail}")
        return "\n".join(lines)


def _guarded(name, function, required=True):
    """Run one check so any exception becomes a failure, never a pass."""
    try:
        ok, detail = function()
    except Exception as exc:  # noqa: BLE001 - fail closed by design
        return CheckResult(
            name, False,
            f"check could not complete ({type(exc).__name__}: {exc})",
            required,
        )
    return CheckResult(name, bool(ok), str(detail), required)


def check_account_config(config_path):
    def run():
        if not config_path:
            return False, "no --account-config supplied"
        if not os.path.exists(config_path):
            return False, f"{config_path} does not exist"
        profile = load_profile(config_path)
        return True, (f"{len(profile.taxonomy)} categories, "
                      f"{len(profile.protected_labels)} protected label(s)")
    return run


def check_account_binding(profile, authenticated_account):
    def run():
        if profile is None:
            return False, "no profile loaded"
        if not authenticated_account:
            return False, "authenticated account unknown"
        assert_profile_matches_account(profile, authenticated_account)
        return True, f"config is bound to {authenticated_account}"
    return run


def check_taxonomy_confirmed(profile, confirmation_path, bound_account):
    def run():
        if profile is None:
            return False, "no profile loaded"
        if not profile.taxonomy:
            return False, "config declares no taxonomy"
        confirmation = load_taxonomy_confirmation(
            confirmation_path, bound_account
        )
        unconfirmed = [
            entry["slug"] for entry in profile.taxonomy
            if not confirmation.check(entry["slug"], entry["digest"])[0]
        ]
        if unconfirmed:
            return False, "unconfirmed: " + ", ".join(sorted(unconfirmed))
        return True, f"all {len(profile.taxonomy)} categories confirmed"
    return run


def protected_drafting_categories(profile):
    """Categories whose messages can carry a configured protected label."""
    if profile is None:
        return frozenset()
    protected = set(profile.protected_labels)
    categories = {
        slug for slug, label in profile.category_labels.items()
        if label in protected
    }
    for rule in profile.evidence_rules:
        if rule.get("label") in protected:
            categories.update(rule.get("require_categories", ()))
    return frozenset(categories)


def check_drafting_approvals(profile, ai_approval_path, bound_account):
    """Every generic category needs approval at its actual risk level."""
    def run():
        if profile is None:
            return False, "no profile loaded"
        generic = sorted(
            slug for slug, mode in (profile.drafting_modes or {}).items()
            if mode == drafting.MODE_GENERIC
        )
        if not generic:
            return True, "no category uses generated wording"
        approvals = drafting.load_ai_drafting_approval(
            ai_approval_path, bound_account, profile.valid_categories
        )
        protected_categories = protected_drafting_categories(profile)
        missing = []
        for slug in generic:
            carries_protected = slug in protected_categories
            approved, reason = approvals.check(
                slug, carries_protected_label=carries_protected
            )
            if not approved:
                missing.append(f"{slug} ({reason})")
        if missing:
            return False, (
                "generic mode without sufficient approval: "
                + "; ".join(missing)
            )
        detail = f"AI drafting approved for {', '.join(generic)}"
        protected_generic = sorted(set(generic) & protected_categories)
        if protected_generic:
            detail += ("; protected-label grant covers "
                       + ", ".join(protected_generic))
        return True, detail
    return run


def check_templates(profile, templates_dir, template_approval_path,
                    bound_account):
    def run():
        if profile is None:
            return False, "no profile loaded"
        template_slugs = sorted(
            slug for slug, mode in (profile.drafting_modes or {}).items()
            if mode == drafting.MODE_TEMPLATE
        )
        if not template_slugs:
            return True, "no category uses fixed templates"
        templates = triage.load_templates(templates_dir)
        approvals = triage.build_template_approvals(
            template_approval_path, (), bound_account
        )
        problems = []
        for slug in template_slugs:
            body = templates.get(slug)
            if body is None:
                problems.append(f"{slug}: no template file")
            elif triage.is_placeholder_template(body):
                problems.append(f"{slug}: still a placeholder")
            elif not approvals.check(slug, body)[0]:
                problems.append(f"{slug}: wording not approved")
        if problems:
            return False, "; ".join(problems)
        return True, f"approved templates for {', '.join(template_slugs)}"
    return run


def check_labels_exist(profile, account_labels):
    def run():
        if profile is None:
            return False, "no profile loaded"
        if account_labels is None:
            return False, "could not read the account's labels"
        wanted = {
            entry["label"] for entry in profile.taxonomy if entry.get("label")
        }
        wanted |= set(profile.protected_labels)
        wanted |= set(profile.system_labels.values())
        missing = sorted(name for name in wanted if name not in account_labels)
        if missing:
            return False, (
                "run setup_labels.py first; missing: " + ", ".join(missing)
            )
        return True, f"all {len(wanted)} configured labels exist"
    return run


def check_private_file(path, description):
    def run():
        if not path:
            return False, f"no {description} path supplied"
        if not os.path.isfile(path):
            return False, f"{path} does not exist or is not a regular file"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode != 0o600:
            return False, f"{path} is mode {mode:03o}, expected 600"
        return True, f"{path} exists, mode 600"
    return run


def check_state_directory(profile):
    def run():
        if profile is None:
            return False, "no profile loaded"
        parent = os.path.dirname(profile.state_path) or "."
        if not os.path.isdir(parent):
            return True, f"{parent} will be created privately on first run"
        mode = stat.S_IMODE(os.stat(parent).st_mode)
        if mode != 0o700:
            return False, f"{parent} is mode {mode:03o}, expected 700"
        return True, f"{parent} exists, mode 700"
    return run


def check_campaign(profile, approval_path, label, body_path, bound_account):
    """Validate an optional campaign's local approval and fixed body."""
    def run():
        supplied = [approval_path, label, body_path]
        if not any(supplied):
            return True, "no campaign requested"
        if not all(supplied):
            return False, (
                "campaign readiness requires --campaign-label, "
                "--campaign-approval, and --campaign-body together"
            )
        from campaign import find_unresolved_placeholders, load_campaign_approval

        with open(body_path, encoding="utf-8") as handle:
            body = handle.read()
        if find_unresolved_placeholders(body):
            return False, "campaign body contains unresolved placeholders"
        approved = load_campaign_approval(
            approval_path, label, bound_account, aliases={}
        )
        if not approved:
            return False, "campaign approval contains no recipients"
        return True, f"campaign approval covers {len(approved)} recipients"
    return run


def build_report(config_path, confirmation_path, ai_approval_path,
                 templates_dir, template_approval_path,
                 authenticated_account, account_labels, *, live=True,
                 token_path=None, campaign_approval_path=None,
                 campaign_label=None, campaign_body_path=None):
    """Assemble a report without contacting Gmail, Gemini, or a broker."""
    report = ReadinessReport(
        account=authenticated_account or "", live=bool(live)
    )

    config_result = _guarded(
        "account config", check_account_config(config_path)
    )
    report.results.append(config_result)

    profile = None
    if config_result.ok:
        try:
            profile = load_profile(config_path)
        except Exception:  # noqa: BLE001 - the explicit check already failed
            profile = None

    bound_account = authenticated_account if live else (
        getattr(profile, "account", "") or ""
    )
    if live:
        report.results.append(_guarded(
            "authenticated account binding",
            check_account_binding(profile, authenticated_account),
        ))
    else:
        report.results.append(CheckResult(
            "authenticated account binding", False,
            "not performed offline; re-run with --live", required=False,
        ))

    report.results.append(_guarded(
        "taxonomy confirmed",
        check_taxonomy_confirmed(profile, confirmation_path, bound_account),
    ))
    report.results.append(_guarded(
        "AI drafting approval",
        check_drafting_approvals(profile, ai_approval_path, bound_account),
    ))
    report.results.append(_guarded(
        "templates",
        check_templates(profile, templates_dir, template_approval_path,
                        bound_account),
    ))
    if live:
        report.results.append(_guarded(
            "Gmail labels exist", check_labels_exist(profile, account_labels)
        ))
    else:
        report.results.append(CheckResult(
            "Gmail labels exist", False,
            "not performed offline; re-run with --live", required=False,
        ))
    if token_path is not None:
        report.results.append(_guarded(
            "OAuth token file", check_private_file(token_path, "token")
        ))
    report.results.append(_guarded(
        "private state directory", check_state_directory(profile)
    ))
    report.results.append(_guarded(
        "campaign artifacts",
        check_campaign(profile, campaign_approval_path, campaign_label,
                       campaign_body_path, bound_account),
    ))
    return report
