"""Static safety regression tests for production Gmail operations."""
import ast
from pathlib import Path


ROOT = Path(__file__).parent
PRODUCTION = [
    ROOT / "campaign.py",
    ROOT / "triage.py",
    ROOT / "gmail_auth.py",
    ROOT / "gmail_common.py",
    ROOT / "gmail_labeler.py",
    ROOT / "gmail_reader.py",
    ROOT / "daily_triage.py",
    ROOT / "setup_labels.py",
    ROOT / "triage_config.py",
    ROOT / "message_safety.py",
    ROOT / "private_runtime.py",
    ROOT / "campaign_audit.py",
    ROOT / "discovery.py",
    ROOT / "discover_taxonomy.py",
    ROOT / "oauth_broker.py",
    ROOT / "broker_client.py",
    ROOT / "broker_crypto.py",
    ROOT / "broker_wsgi.py",
    ROOT / "approve_account.py",
    ROOT / "readiness.py",
    ROOT / "check_readiness.py",
    ROOT / "taxonomy.py",
    ROOT / "drafting.py",
    ROOT / "migrate_account.py",
    ROOT / "account_profile.py",
    ROOT / "triage_limits.py",
    ROOT / "local_notifier.py",
    ROOT / "review_report.py",
    ROOT / "connection.py",
    ROOT / "connection_archive.py",
    ROOT / "connection_expiry.py",
    ROOT / "connect_account.py",
    ROOT / "connection_kms.py",
    ROOT / "connection_notify.py",
    ROOT / "connection_schedule.py",
    ROOT / "connection_tokens.py",
    ROOT / "hosted_status.py",
    ROOT / "hosted_wsgi.py",
    ROOT / "hosted_runner.py",
    ROOT / "hosted_dashboard.py",
    ROOT / "hosted_dashboard_wsgi.py",
    ROOT / "hosted_settings.py",
    ROOT / "hosted_control.py",
    ROOT / "web_status.py",
]

GMAIL_WRITE_METHODS = {
    "send", "delete", "batchDelete", "batchModify", "insert", "import_",
    "untrash", "create", "modify", "trash", "update", "patch",
}
ALLOWED_WRITE_SITES = {
    ("campaign.py", "create_drafts", "users().drafts().create"),
    ("campaign.py", "trash_drafts", "users().messages().trash"),
    ("triage.py", "execute_plan", "users().drafts().create"),
    ("daily_triage.py", "_create_reply_draft", "users().drafts().create"),
    ("gmail_labeler.py", "apply_labels", "users().messages().modify"),
    ("setup_labels.py", "apply_label_setup", "users().labels().create"),
}


def _is_allowed_write(path, function_name, call_path):
    return any(
        path.name == filename
        and function_name == allowed_function
        and call_path.endswith(suffix)
        for filename, allowed_function, suffix in ALLOWED_WRITE_SITES
    )


def _call_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return f"{_call_path(node.func)}()"
    return ""


def _calls_with_scope(tree):
    """Return each call with its nearest enclosing function.

    Walking each FunctionDef separately double-counts nested functions, while
    walking only functions misses a dangerous module-level mutation. The
    explicit stack closes both guard blind spots.
    """
    found = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def _visit_function(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _visit_function
        visit_AsyncFunctionDef = _visit_function

        def visit_Call(self, node):
            found.append((self.stack[-1] if self.stack else "<module>", node))
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def _is_safe_computed_getattr(node):
    """Only argparse field iteration may use a computed attribute name."""
    target = node.args[0] if node.args else None
    return isinstance(target, ast.Name) and target.id == "args"


def test_production_contains_no_gmail_send_or_unapproved_write_call():
    violations = []
    found_allowed = set()
    for path in PRODUCTION:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for function_name, node in _calls_with_scope(tree):
                call_path = _call_path(node.func)
                method = (
                    node.func.attr if isinstance(node.func, ast.Attribute) else ""
                )

                if method == "send":
                    violations.append(f"{path.name}:{node.lineno}: {call_path}")
                if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                    attribute = node.args[1] if len(node.args) >= 2 else None
                    if not (isinstance(attribute, ast.Constant)
                            and isinstance(attribute.value, str)):
                        if not _is_safe_computed_getattr(node):
                            violations.append(
                                f"{path.name}:{node.lineno}: computed getattr "
                                "name cannot be statically audited for Gmail "
                                "mutations"
                            )
                    elif attribute.value in GMAIL_WRITE_METHODS:
                        violations.append(
                            f"{path.name}:{node.lineno}: dynamic Gmail mutation "
                            f"getattr {attribute.value}"
                        )

                if "users()" in call_path and method in GMAIL_WRITE_METHODS:
                    site = next((
                        allowed for allowed in ALLOWED_WRITE_SITES
                        if path.name == allowed[0]
                        and function_name == allowed[1]
                        and call_path.endswith(allowed[2])
                    ), None)
                    if not _is_allowed_write(path, function_name, call_path):
                        violations.append(
                            f"{path.name}:{node.lineno}: unapproved Gmail write "
                            f"in {function_name}(): {call_path}"
                        )
                    elif site is not None:
                        found_allowed.add(site)

    assert violations == [], "\n".join(violations)
    assert found_allowed == ALLOWED_WRITE_SITES, (
        "approved Gmail write inventory drifted; missing exact sites: "
        f"{sorted(ALLOWED_WRITE_SITES - found_allowed)}"
    )


def test_trash_is_approved_only_for_campaign_rollback():
    trash_sites = {
        (filename, function)
        for filename, function, suffix in ALLOWED_WRITE_SITES
        if suffix.endswith("messages().trash")
    }

    assert trash_sites == {("campaign.py", "trash_drafts")}


def test_approved_method_in_the_wrong_function_is_still_rejected():
    """Guard the call-site boundary, not just the Gmail method name."""
    assert not _is_allowed_write(
        ROOT / "campaign.py",
        "create_drafts",
        "service.users().messages().trash",
    )
    assert not _is_allowed_write(
        ROOT / "daily_triage.py",
        "execute_daily_plan",
        "service.users().drafts().create",
    )


def test_only_cli_args_may_use_a_computed_getattr_name():
    safe = ast.parse("getattr(args, field_name)").body[0].value
    unsafe = ast.parse("getattr(service, method_name)").body[0].value

    assert _is_safe_computed_getattr(safe)
    assert not _is_safe_computed_getattr(unsafe)


def test_label_modify_payload_is_add_only():
    payloads = []
    for path in PRODUCTION:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        payloads.extend(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Dict)
            and any(isinstance(key, ast.Constant) and key.value == "addLabelIds"
                    for key in node.keys)
        )
    assert payloads, "expected an addLabelIds payload"
    for payload in payloads:
        keys = {key.value for key in payload.keys if isinstance(key, ast.Constant)}
        assert keys == {"addLabelIds"}
