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
    ROOT / "taxonomy.py",
    ROOT / "drafting.py",
    ROOT / "migrate_account.py",
    ROOT / "account_profile.py",
]

GMAIL_WRITE_METHODS = {
    "send", "delete", "batchDelete", "batchModify", "insert", "import_",
    "untrash", "create", "modify", "trash", "update", "patch",
}
ALLOWED_WRITE_SUFFIXES = {
    "users().drafts().create",
    "users().messages().modify",
    "users().messages().trash",
}


def _is_allowed_write(path, call_path):
    if any(call_path.endswith(suffix) for suffix in ALLOWED_WRITE_SUFFIXES):
        return True
    return (
        path.name == "setup_labels.py"
        and call_path.endswith("users().labels().create")
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


def test_production_contains_no_gmail_send_or_unapproved_write_call():
    violations = []
    for path in PRODUCTION:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_path = _call_path(node.func)
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""

            if method == "send":
                violations.append(f"{path.name}:{node.lineno}: {call_path}")
            if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in GMAIL_WRITE_METHODS):
                violations.append(
                    f"{path.name}:{node.lineno}: dynamic Gmail mutation getattr "
                    f"{node.args[1].value}"
                )

            if "users()" in call_path and method in GMAIL_WRITE_METHODS:
                if not _is_allowed_write(path, call_path):
                    violations.append(
                        f"{path.name}:{node.lineno}: unapproved Gmail write {call_path}"
                    )

    assert violations == [], "\n".join(violations)


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
