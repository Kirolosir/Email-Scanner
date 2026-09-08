"""Offline tests for the hosted status service.

The properties being pinned, in the order they matter if the endpoint is ever
reached by someone who should not have reached it:

  H1  every request path is a read - nothing served can mutate state
  H2  no response carries the connected address
  H3  the bearer is required, compared constant-time, and short ones are
      refused at boot rather than at request time
  H4  /healthz needs no credential and therefore discloses nothing
  H5  this module cannot reach a token, by import
  H6  a volume that cannot support the state layer refuses to boot
"""
import ast
import datetime as dt
import json
from pathlib import Path

import pytest

import connection as conn
import hosted_status
from hosted_status import (
    HostedConfig,
    HostedConfigError,
    HostedStatusApp,
    status_document,
    verify_durable_state_root,
)


A = "coach@example.test"
BEARER = "b" * 48
T0 = dt.datetime(2026, 9, 7, 18, 0, tzinfo=dt.timezone.utc)
SOURCE = Path("hosted_status.py").read_text(encoding="utf-8")


def _config(tmp_path, **kwargs):
    kwargs.setdefault("require_forwarded_https", False)
    return HostedConfig(tmp_path, BEARER, **kwargs)


def _app(tmp_path, now=T0, **kwargs):
    return HostedStatusApp(_config(tmp_path, **kwargs), clock=lambda: now)


def _call(app, path="/", method="GET", bearer=BEARER, **extra):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path}
    if bearer is not None:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {bearer}"
    environ.update(extra)

    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    chunks = app(environ, start_response)
    captured["body"] = b"".join(chunks).decode("utf-8")
    try:
        captured["json"] = json.loads(captured["body"])
    except json.JSONDecodeError:
        captured["json"] = None
    return captured


def _connect(tmp_path, now=T0):
    return conn.connect(tmp_path, A, timezone="America/New_York",
                        run_at="18:00", now=now)


# ---------------------------------------------------------------------
# H1  read-only
# ---------------------------------------------------------------------

REQUEST_PATH_NAMES = {
    "HostedStatusApp", "status_document", "_read_json", "_last_run",
    "_last_successful_run",
}
MUTATING = {
    "unlink", "remove", "rmtree", "replace", "rename", "mkstemp", "mkdir",
    "makedirs", "write", "write_text", "write_bytes", "atomic_write_json",
    "ensure_private_directory", "chmod", "connect", "disconnect", "store_token",
    "truncate", "flock",
}


def _nodes_for(names):
    tree = ast.parse(SOURCE)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            yield node


def test_no_request_path_can_mutate_anything():
    """H1: scoped per function, the way the no-send audit is scoped.

    verify_durable_state_root legitimately writes - it probes the volume at
    boot. So the guard covers the code a request can actually reach, which is
    the property that matters, rather than the whole file.
    """
    found = [node.name for node in _nodes_for(REQUEST_PATH_NAMES)]
    assert sorted(found) == sorted(REQUEST_PATH_NAMES), (
        f"request-path guard is looking for functions that moved: {found}"
    )

    violations = []
    for node in _nodes_for(REQUEST_PATH_NAMES):
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                name = getattr(inner.func, "attr",
                               getattr(inner.func, "id", ""))
                if name in MUTATING:
                    violations.append(f"{node.name}: {name}() at line {inner.lineno}")
            if isinstance(inner, ast.Call) and \
                    getattr(inner.func, "attr", "") == "open":
                for keyword in inner.keywords:
                    if keyword.arg == "mode":
                        violations.append(f"{node.name}: open(mode=) writable")
                for arg in inner.args:
                    if isinstance(arg, ast.Constant) and \
                            isinstance(arg.value, str) and \
                            any(c in arg.value for c in "wax+"):
                        violations.append(f"{node.name}: open({arg.value!r})")

    assert violations == [], "request path can mutate state:\n" + "\n".join(violations)


def test_a_write_verb_is_refused(tmp_path):
    _connect(tmp_path)
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = _call(_app(tmp_path), method=method)
        assert response["status"].startswith("405")
        assert "read-only" in response["json"]["error"]


def test_a_write_verb_is_refused_even_with_a_valid_bearer(tmp_path):
    """Authentication is not authorisation to mutate; there is nothing to hit."""
    _connect(tmp_path)
    response = _call(_app(tmp_path), method="DELETE", bearer=BEARER)
    assert response["status"].startswith("405")


def test_serving_a_request_leaves_the_state_untouched(tmp_path):
    """The observable half of H1."""
    _connect(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    _call(_app(tmp_path))
    after = {p.name: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after and before != {}


# ---------------------------------------------------------------------
# H2  no address ever leaves
# ---------------------------------------------------------------------

def test_the_connected_address_never_appears_in_a_response(tmp_path):
    _connect(tmp_path)
    response = _call(_app(tmp_path))
    assert response["status"].startswith("200")
    assert A not in response["body"]
    assert "coach" not in response["body"]
    assert "@" not in response["body"]


def test_the_status_document_itself_carries_no_address(tmp_path):
    """Pinned at the source, not only at the boundary."""
    _connect(tmp_path)
    body = json.dumps(status_document(tmp_path, T0))
    assert A not in body and "@" not in body


def test_a_connection_is_reported_by_its_opaque_id(tmp_path):
    _connect(tmp_path)
    document = status_document(tmp_path, T0)
    assert document["connection"]["state"] == "connected"
    assert document["connection"]["id"] == "active"


def test_configuration_is_reported_because_it_discloses_nobody(tmp_path):
    _connect(tmp_path)
    connection = status_document(tmp_path, T0)["connection"]
    assert connection["run_at"] == "18:00"
    assert connection["timezone"] == "America/New_York"
    assert connection["limits"]["max_drafts"] == 5


def test_a_vacant_deployment_says_so(tmp_path):
    document = status_document(tmp_path, T0)
    assert document["connection"] == {"state": "vacant"}
    assert "expiry" not in document


def test_a_damaged_record_is_not_reported_as_vacant(tmp_path):
    """Reading corruption as "nobody is connected" is how a takeover hides."""
    conn.record_path(tmp_path).write_text("{not json", encoding="utf-8")
    document = status_document(tmp_path, T0)
    assert document["connection"]["state"] == "unreadable"
    assert document["connection"]["state"] != "vacant"


def test_a_damaged_record_detail_carries_no_path_or_content(tmp_path):
    conn.record_path(tmp_path).write_text("{not json", encoding="utf-8")
    detail = status_document(tmp_path, T0)["connection"]["detail"]
    assert str(tmp_path) not in detail
    assert "not json" not in detail


# ---------------------------------------------------------------------
# expiry is carried through, still labelled a prediction
# ---------------------------------------------------------------------

def test_the_expiry_estimate_is_included_and_labelled(tmp_path):
    _connect(tmp_path)
    document = status_document(tmp_path, T0 + dt.timedelta(days=1))
    assert document["expiry"]["basis"] == "prediction"
    assert document["expiry"]["state"] == "healthy"


def test_a_successful_run_after_the_window_still_outranks_the_estimate(tmp_path):
    connection = _connect(tmp_path)
    (Path(connection.directory) / "daily-status.json").write_text(
        json.dumps({"outcome": "success",
                    "finished_at": (T0 + dt.timedelta(days=9)).isoformat()}),
        encoding="utf-8",
    )
    document = status_document(tmp_path, T0 + dt.timedelta(days=10))
    assert document["expiry"]["evidence_overrides_prediction"] is True
    assert document["expiry"]["state"] == "healthy"


def test_a_failed_run_is_not_evidence_of_a_working_token(tmp_path):
    connection = _connect(tmp_path)
    (Path(connection.directory) / "daily-status.json").write_text(
        json.dumps({"outcome": "failure",
                    "finished_at": (T0 + dt.timedelta(days=9)).isoformat()}),
        encoding="utf-8",
    )
    document = status_document(tmp_path, T0 + dt.timedelta(days=10))
    assert document["expiry"]["evidence_overrides_prediction"] is False
    assert document["expiry"]["state"] == "expired"


def test_the_last_run_carries_no_counts_or_message_detail(tmp_path):
    connection = _connect(tmp_path)
    (Path(connection.directory) / "daily-status.json").write_text(
        json.dumps({"outcome": "success", "finished_at": T0.isoformat(),
                    "subjects": ["a private subject line"],
                    "counts": {"scanned": 12}}),
        encoding="utf-8",
    )
    response = _call(_app(tmp_path))
    assert "private subject" not in response["body"]
    assert "scanned" not in response["body"]
    assert response["json"]["last_run"]["outcome"] == "success"


# ---------------------------------------------------------------------
# H3  the bearer
# ---------------------------------------------------------------------

def test_no_bearer_is_unauthorized(tmp_path):
    _connect(tmp_path)
    response = _call(_app(tmp_path), bearer=None)
    assert response["status"].startswith("401")


def test_a_wrong_bearer_is_unauthorized(tmp_path):
    _connect(tmp_path)
    response = _call(_app(tmp_path), bearer="x" * 48)
    assert response["status"].startswith("401")


def test_an_unauthorized_response_discloses_nothing_about_the_connection(tmp_path):
    _connect(tmp_path)
    response = _call(_app(tmp_path), bearer=None)
    assert response["json"] == {"error": "unauthorized"}
    assert "connected" not in response["body"]
    assert "vacant" not in response["body"]


def test_an_unauthorized_response_offers_the_scheme(tmp_path):
    response = _call(_app(tmp_path), bearer=None)
    assert response["headers"].get("WWW-Authenticate") == "Bearer"


def test_a_non_bearer_scheme_is_refused(tmp_path):
    _connect(tmp_path)
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/",
               "HTTP_AUTHORIZATION": f"Basic {BEARER}"}
    captured = {}
    body = b"".join(_app(tmp_path)(environ, lambda s, h: captured.update(
        status=s, headers=dict(h))))
    assert captured["status"].startswith("401")
    assert b"unauthorized" in body


def test_the_bearer_is_compared_in_constant_time():
    """A length-sensitive == would leak the prefix a byte at a time."""
    assert "hmac.compare_digest" in SOURCE
    assert "compare_digest" in SOURCE

    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "bearer_matches":
            comparisons = [n for n in ast.walk(node) if isinstance(n, ast.Compare)]
            assert comparisons == [], (
                "bearer_matches uses a plain comparison; that is a timing oracle"
            )
            return
    pytest.fail("bearer_matches not found")


@pytest.mark.parametrize("bad", ["", "short", "a" * 31])
def test_a_weak_bearer_is_refused_at_boot(tmp_path, bad):
    with pytest.raises(HostedConfigError):
        HostedConfig(tmp_path, bad, verify_root=False)


def test_a_bearer_of_exactly_the_minimum_is_accepted(tmp_path):
    assert HostedConfig(tmp_path, "a" * 32, verify_root=False)


def test_the_bearer_is_not_readable_as_a_plain_attribute(tmp_path):
    config = HostedConfig(tmp_path, BEARER, verify_root=False)
    assert BEARER not in repr(config)
    assert not hasattr(config, "operator_bearer")


# ---------------------------------------------------------------------
# H4  healthz
# ---------------------------------------------------------------------

def test_healthz_needs_no_credential(tmp_path):
    response = _call(_app(tmp_path), path="/healthz", bearer=None)
    assert response["status"].startswith("200")
    assert response["json"] == {"status": "ok"}


def test_healthz_does_not_say_whether_anyone_is_connected(tmp_path):
    _connect(tmp_path)
    connected = _call(_app(tmp_path), path="/healthz", bearer=None)
    vacant_root = tmp_path / "empty"
    vacant_root.mkdir()
    vacant = _call(_app(vacant_root), path="/healthz", bearer=None)
    assert connected["body"] == vacant["body"]


def test_an_unknown_route_is_a_404_not_a_hint(tmp_path):
    response = _call(_app(tmp_path), path="/connection/disconnect")
    assert response["status"].startswith("404")


# ---------------------------------------------------------------------
# https
# ---------------------------------------------------------------------

def test_a_forwarded_plaintext_request_is_refused_when_https_is_required(tmp_path):
    app = _app(tmp_path, require_forwarded_https=True)
    response = _call(app, HTTP_X_FORWARDED_PROTO="http")
    assert response["status"].startswith("400")


def test_a_forwarded_https_request_is_served(tmp_path):
    _connect(tmp_path)
    app = _app(tmp_path, require_forwarded_https=True)
    response = _call(app, HTTP_X_FORWARDED_PROTO="https")
    assert response["status"].startswith("200")


def test_the_first_forwarded_proto_is_the_one_that_counts(tmp_path):
    _connect(tmp_path)
    app = _app(tmp_path, require_forwarded_https=True)
    assert _call(app, HTTP_X_FORWARDED_PROTO="https, http"
                 )["status"].startswith("200")
    assert _call(app, HTTP_X_FORWARDED_PROTO="http, https"
                 )["status"].startswith("400")


def test_https_is_checked_before_the_bearer(tmp_path):
    """A credential must not be read off a connection declared plaintext."""
    app = _app(tmp_path, require_forwarded_https=True)
    response = _call(app, bearer=BEARER, HTTP_X_FORWARDED_PROTO="http")
    assert response["status"].startswith("400")


# ---------------------------------------------------------------------
# H5  it cannot reach a token
# ---------------------------------------------------------------------

def test_the_module_cannot_reach_a_credential_by_import():
    tree = ast.parse(SOURCE)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("connection_tokens", "connection_kms", "gmail_auth",
                      "gmail_common", "gmail_reader", "gmail_labeler",
                      "googleapiclient", "google", "drafting", "gemini_client",
                      "connection_archive", "subprocess", "requests"):
        assert forbidden not in imported, (
            f"hosted_status imports {forbidden}; a compromise of the status "
            "endpoint must yield status, not mail"
        )


def test_no_response_can_contain_a_token_field(tmp_path):
    connection = _connect(tmp_path)
    (Path(connection.directory) / "token.enc.json").write_text(
        json.dumps({"ciphertext": "SEALED-VALUE", "wrapped_key": "KEY-VALUE"}),
        encoding="utf-8",
    )
    response = _call(_app(tmp_path))
    for leaked in ("SEALED", "KEY-VALUE", "ciphertext", "wrapped_key",
                   "refresh_token"):
        assert leaked not in response["body"]


# ---------------------------------------------------------------------
# H6  the state volume
# ---------------------------------------------------------------------

def test_a_real_directory_passes_the_probe(tmp_path):
    assert verify_durable_state_root(tmp_path) is True


def test_the_probe_leaves_nothing_behind(tmp_path):
    verify_durable_state_root(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_missing_state_root_refuses_to_boot(tmp_path):
    with pytest.raises(HostedConfigError) as caught:
        verify_durable_state_root(tmp_path / "not-mounted")
    assert "durable" in str(caught.value).lower()


def test_a_file_is_not_a_state_root(tmp_path):
    target = tmp_path / "a-file"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(HostedConfigError):
        verify_durable_state_root(target)


def test_a_volume_without_atomic_rename_refuses_to_boot(tmp_path, monkeypatch):
    """The GCS-FUSE case, which would otherwise lose state silently."""
    def no_rename(*_args, **_kwargs):
        raise OSError("operation not supported")

    monkeypatch.setattr(hosted_status.os, "replace", no_rename)
    with pytest.raises(HostedConfigError) as caught:
        verify_durable_state_root(tmp_path)
    assert "atomic rename" in str(caught.value)


def test_a_volume_without_advisory_locking_refuses_to_boot(tmp_path, monkeypatch):
    """The double refuses only the exclusive acquire.

    A double that failed on ANY flock call would let this pass even with the
    acquire deleted, because the release would still raise - the probe would
    then be proving nothing about whether a lock can be taken. Refusing only
    LOCK_EX makes the test fail exactly when the acquire stops happening.
    """
    real_lock_ex = hosted_status.fcntl.LOCK_EX

    def only_exclusive(_descriptor, operation):
        if operation & real_lock_ex:
            raise OSError("operation not supported")
        return None

    monkeypatch.setattr(hosted_status.fcntl, "flock", only_exclusive)
    with pytest.raises(HostedConfigError) as caught:
        verify_durable_state_root(tmp_path)
    assert "locking" in str(caught.value)


def test_the_probe_runs_on_construction_by_default(tmp_path, monkeypatch):
    def no_lock(*_args, **_kwargs):
        raise OSError("nope")

    monkeypatch.setattr(hosted_status.fcntl, "flock", no_lock)
    with pytest.raises(HostedConfigError):
        HostedConfig(tmp_path, BEARER)


# ---------------------------------------------------------------------
# Configuration from the environment
# ---------------------------------------------------------------------

def test_configuration_reads_the_environment(tmp_path):
    config = HostedConfig.from_environment({
        "HOSTED_STATE_ROOT": str(tmp_path),
        "HOSTED_OPERATOR_BEARER": BEARER,
    }, verify_root=False)
    assert config.state_root == tmp_path
    assert config.bearer_matches(BEARER)


def test_quotes_and_whitespace_from_a_dashboard_are_stripped(tmp_path):
    config = HostedConfig.from_environment({
        "HOSTED_STATE_ROOT": f'  "{tmp_path}"  ',
        "HOSTED_OPERATOR_BEARER": f"'{BEARER}'",
    }, verify_root=False)
    assert config.state_root == tmp_path
    assert config.bearer_matches(BEARER)


def test_https_is_required_unless_explicitly_disabled(tmp_path):
    def build(value):
        return HostedConfig.from_environment({
            "HOSTED_STATE_ROOT": str(tmp_path),
            "HOSTED_OPERATOR_BEARER": BEARER,
            "HOSTED_REQUIRE_FORWARDED_HTTPS": value,
        }, verify_root=False).require_forwarded_https

    assert build("") is True
    assert build("anything") is True
    assert build("false") is False
    assert build("0") is False


def test_a_missing_state_root_variable_is_refused():
    with pytest.raises(HostedConfigError):
        HostedConfig.from_environment({"HOSTED_OPERATOR_BEARER": BEARER},
                                      verify_root=False)


# ---------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------

def test_an_unexpected_error_does_not_return_a_traceback(tmp_path):
    app = _app(tmp_path)

    def explode():
        raise RuntimeError("secret detail from /a/private/path")

    app.clock = explode
    _connect(tmp_path)
    response = _call(app)
    assert response["status"].startswith("500")
    assert response["json"] == {"error": "internal error"}
    assert "private/path" not in response["body"]
    assert "Traceback" not in response["body"]


def test_every_response_is_json_and_uncached(tmp_path):
    _connect(tmp_path)
    for path, bearer in (("/", BEARER), ("/healthz", None), ("/nope", BEARER)):
        response = _call(_app(tmp_path), path=path, bearer=bearer)
        assert response["headers"]["Content-Type"].startswith("application/json")
        assert response["headers"]["Cache-Control"] == "no-store"
        assert response["headers"]["X-Content-Type-Options"] == "nosniff"


def test_the_entry_point_builds_nothing_at_import():
    """Importing must not require a configured environment."""
    import hosted_wsgi
    assert hosted_wsgi._app is None
