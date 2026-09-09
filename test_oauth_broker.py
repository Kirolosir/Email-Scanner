"""Offline tests for the hosted OAuth broker.

Nothing here starts a listener, opens a socket, or contacts Google. The WSGI
app is driven directly and the token exchange is injected.

The properties under test are the ones that decide whether this is safe to
stand up at all: CSRF state handling, PKCE, where the client secret can
appear, what is persisted, and who can collect the result.
"""
import json
import os
import urllib.parse

import pytest

import broker_client
import broker_crypto
import oauth_broker
from broker_crypto import SealError, generate_operator_keypair, seal, unseal
from oauth_broker import (
    STATE_TTL_SECONDS,
    BrokerConfig,
    BrokerConfigError,
    MemoryStore,
    OAuthBroker,
)

CLIENT_SECRET = "super-secret-client-value-do-not-leak"
BEARER = "o" * 48


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _config(**overrides):
    _private, public = generate_operator_keypair()
    kwargs = dict(
        client_id="client-id.apps.googleusercontent.com",
        client_secret=CLIENT_SECRET,
        redirect_uri="https://broker.example.test/callback",
        operator_public_key=public,
        operator_bearer=BEARER,
    )
    kwargs.update(overrides)
    return BrokerConfig(**kwargs), kwargs["operator_public_key"]


def _broker(exchange=None, clock=None):
    private, public = generate_operator_keypair()
    config = BrokerConfig(
        client_id="client-id.apps.googleusercontent.com",
        client_secret=CLIENT_SECRET,
        redirect_uri="https://broker.example.test/callback",
        operator_public_key=public,
        operator_bearer=BEARER,
    )
    calls = []

    def default_exchange(endpoint, payload):
        calls.append({"endpoint": endpoint, "payload": dict(payload)})
        return {"refresh_token": "1//real-refresh-token",
                "scope": "https://www.googleapis.com/auth/gmail.modify",
                "token_type": "Bearer"}

    broker = OAuthBroker(config, exchange_fn=exchange or default_exchange,
                         clock=clock or FakeClock())
    return broker, private, calls


def _request(app, path, query="", headers=None, scheme="https", method="GET"):
    captured = {}

    def start_response(status, response_headers):
        captured["status"] = status
        captured["headers"] = dict(response_headers)

    environ = {
        "PATH_INFO": path, "QUERY_STRING": query,
        "REQUEST_METHOD": method, "wsgi.url_scheme": scheme,
    }
    environ.update(headers or {})
    body = b"".join(app(environ, start_response))
    captured["body"] = body
    return captured


def _authorize(broker):
    """Walk an owner through /start and return (invite_id, state)."""
    invite = broker.create_invite()
    response = _request(broker, f"/start/{invite}")
    location = response["headers"]["Location"]
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    return invite, query["state"][0], query


# --------------------------------------------------------------------
# Configuration refuses unsafe setups
# --------------------------------------------------------------------

@pytest.mark.parametrize("override,message", [
    ({"client_id": ""}, "client_id"),
    ({"client_secret": ""}, "client_secret"),
    ({"redirect_uri": ""}, "redirect_uri"),
    ({"redirect_uri": "http://broker.example.test/callback"}, "https"),
    ({"operator_public_key": b"too-short"}, "32 raw bytes"),
    ({"operator_bearer": "short"}, "at least 32"),
])
def test_unsafe_configuration_is_refused(override, message):
    with pytest.raises(BrokerConfigError, match=message):
        _config(**override)


def test_plaintext_redirect_uri_is_refused():
    """An authorization code must never cross a plaintext connection."""
    with pytest.raises(BrokerConfigError, match="https"):
        _config(redirect_uri="http://broker.example.test/callback")


def test_http_requests_are_rejected():
    broker, _private, _calls = _broker()
    response = _request(broker, "/callback", scheme="http")
    assert response["status"].startswith("400")
    assert "HTTPS" in response["body"].decode()


@pytest.mark.parametrize("path,title", [
    ("/", "Serpone Emails"),
    ("/privacy", "Privacy policy"),
    ("/terms", "Terms of service"),
])
def test_public_information_pages_are_available_over_https(path, title):
    broker, _private, _calls = _broker()
    response = _request(broker, path)

    assert response["status"] == "200 OK"
    assert response["headers"]["Content-Type"] == "text/html; charset=utf-8"
    assert response["headers"]["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response["headers"]["Content-Security-Policy"]
    assert title in response["body"].decode("utf-8")
    assert CLIENT_SECRET.encode() not in response["body"]
    assert BEARER.encode() not in response["body"]


def test_public_pages_explain_mailbox_controls():
    broker, _private, _calls = _broker()
    home = _request(broker, "/")["body"].decode("utf-8")
    privacy = _request(broker, "/privacy")["body"].decode("utf-8")

    assert "never sends email automatically" in home
    assert "Only one Google account" in privacy
    assert "disconnect" in privacy
    assert "Google Gemini" in privacy


# --------------------------------------------------------------------
# CSRF state
# --------------------------------------------------------------------

def test_state_is_high_entropy_and_unique():
    broker, _private, _calls = _broker()
    seen = set()
    for _ in range(25):
        _invite, state, _query = _authorize(broker)
        # token_urlsafe(32) -> 43 chars of base64url, i.e. 256 bits.
        assert len(state) >= 40
        seen.add(state)
    assert len(seen) == 25, "state values repeated"


def test_callback_without_a_known_state_is_refused():
    broker, _private, calls = _broker()
    _invite, _state, _query = _authorize(broker)

    response = _request(broker, "/callback",
                        query="code=abc&state=forged-state")
    assert response["status"].startswith("400")
    assert calls == [], "a forged state reached the token exchange"


def test_state_is_single_use():
    """A replayed callback must not produce a second exchange."""
    broker, _private, calls = _broker()
    invite, state, _query = _authorize(broker)

    first = _request(broker, "/callback", query=f"code=abc&state={state}")
    assert first["status"].startswith("200")
    assert len(calls) == 1

    second = _request(broker, "/callback", query=f"code=abc&state={state}")
    assert second["status"].startswith("400")
    assert len(calls) == 1, "a replayed state was exchanged twice"


def test_state_expires():
    clock = FakeClock()
    broker, _private, calls = _broker(clock=clock)
    _invite, state, _query = _authorize(broker)

    clock.advance(STATE_TTL_SECONDS + 1)
    response = _request(broker, "/callback", query=f"code=abc&state={state}")

    assert response["status"].startswith("400")
    assert calls == []


def test_callback_without_a_code_is_refused():
    broker, _private, calls = _broker()
    _invite, state, _query = _authorize(broker)

    response = _request(broker, "/callback", query=f"state={state}")
    assert response["status"].startswith("400")
    assert calls == []


def test_provider_error_is_reported_without_exchanging():
    broker, _private, calls = _broker()
    _invite, state, _query = _authorize(broker)

    response = _request(broker, "/callback",
                        query=f"error=access_denied&state={state}")
    assert response["status"].startswith("400")
    assert calls == []


# --------------------------------------------------------------------
# PKCE
# --------------------------------------------------------------------

def test_start_sends_an_s256_challenge_never_the_verifier():
    broker, _private, _calls = _broker()
    _invite, _state, query = _authorize(broker)

    assert query["code_challenge_method"] == ["S256"]
    challenge = query["code_challenge"][0]
    assert challenge and "=" not in challenge
    assert "code_verifier" not in query


def test_exchange_sends_the_verifier_matching_the_challenge():
    from base64 import urlsafe_b64encode
    from hashlib import sha256

    broker, _private, calls = _broker()
    _invite, state, query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    verifier = calls[0]["payload"]["code_verifier"]
    expected = urlsafe_b64encode(
        sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert expected == query["code_challenge"][0]


# --------------------------------------------------------------------
# The client secret never becomes public
# --------------------------------------------------------------------

def test_client_secret_never_appears_in_the_authorization_redirect():
    broker, _private, _calls = _broker()
    _invite, _state, _query = _authorize(broker)
    response = _request(broker, f"/start/{broker.create_invite()}")

    location = response["headers"]["Location"]
    assert CLIENT_SECRET not in location
    assert "client_secret" not in location


def test_client_secret_never_appears_in_any_response_body_or_header():
    broker, _private, _calls = _broker()
    invite, state, _query = _authorize(broker)

    responses = [
        _request(broker, f"/start/{invite}"),
        _request(broker, "/callback", query=f"code=abc&state={state}"),
        _request(broker, "/callback", query="code=abc&state=bogus"),
        _request(broker, f"/pickup/{invite}"),
        _request(broker, "/nope"),
    ]
    for response in responses:
        blob = response["body"].decode("utf-8", "replace") + json.dumps(
            response.get("headers", {})
        )
        assert CLIENT_SECRET not in blob


def test_client_secret_is_sent_only_to_the_token_endpoint():
    broker, _private, calls = _broker()
    _invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    assert len(calls) == 1
    assert calls[0]["endpoint"] == oauth_broker.GOOGLE_TOKEN_ENDPOINT
    assert calls[0]["payload"]["client_secret"] == CLIENT_SECRET


def test_success_page_shows_no_token_or_code():
    broker, _private, _calls = _broker()
    _invite, state, _query = _authorize(broker)
    response = _request(broker, "/callback",
                        query=f"code=the-auth-code&state={state}")

    body = response["body"].decode()
    assert response["status"].startswith("200")
    assert "the-auth-code" not in body
    assert "refresh" not in body.lower()
    assert "1//real-refresh-token" not in body


def test_exchange_failure_does_not_leak_the_code():
    def failing(endpoint, payload):
        raise RuntimeError(f"boom with code {payload['code']}")

    broker, _private, _calls = _broker(exchange=failing)
    _invite, state, _query = _authorize(broker)
    response = _request(broker, "/callback",
                        query=f"code=leaky-code&state={state}")

    assert response["status"].startswith("502")
    assert "leaky-code" not in response["body"].decode()


# --------------------------------------------------------------------
# Only ciphertext is retained
# --------------------------------------------------------------------

def test_only_sealed_ciphertext_is_stored():
    broker, private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    stored = broker.pickups.peek(invite)
    assert stored is not None
    assert b"1//real-refresh-token" not in stored, (
        "the refresh token was stored in a readable form"
    )
    recovered = json.loads(unseal(private, stored).decode())
    assert recovered["refresh_token"] == "1//real-refresh-token"


def test_broker_cannot_decrypt_what_it_sealed():
    """The broker holds only a public key, so a compromised broker yields
    ciphertext rather than a usable credential."""
    broker, _private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    sealed = broker.pickups.peek(invite)
    other_private, _other_public = generate_operator_keypair()
    with pytest.raises(SealError):
        unseal(other_private, sealed)


def test_missing_refresh_token_is_reported_and_stores_nothing():
    def no_refresh(endpoint, payload):
        return {"access_token": "short-lived-only"}

    broker, _private, _calls = _broker(exchange=no_refresh)
    invite, state, _query = _authorize(broker)
    response = _request(broker, "/callback", query=f"code=abc&state={state}")

    assert response["status"].startswith("400")
    assert broker.pickups.peek(invite) is None


# --------------------------------------------------------------------
# Invites and pickup
# --------------------------------------------------------------------

def test_unknown_and_used_invites_are_indistinguishable():
    """An attacker must not be able to enumerate valid invite ids."""
    broker, _private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    used = _request(broker, f"/start/{invite}")
    unknown = _request(broker, "/start/never-existed")

    assert used["status"] == unknown["status"]
    assert used["body"] == unknown["body"]


def test_invite_cannot_be_reused_after_a_successful_sign_in():
    broker, _private, calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    assert _request(broker, f"/start/{invite}")["status"].startswith("404")
    assert len(calls) == 1


def test_pickup_requires_the_operator_bearer():
    broker, _private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    for header in ({}, {"HTTP_AUTHORIZATION": "Bearer wrong"},
                   {"HTTP_AUTHORIZATION": BEARER},
                   {"HTTP_AUTHORIZATION": "Bearer "},
                   {"HTTP_AUTHORIZATION": f"Bearer {BEARER[:-1]}"}):
        response = _request(broker, f"/pickup/{invite}", headers=header)
        assert response["status"].startswith("401"), header
    assert broker.pickups.peek(invite) is not None, "a failed pickup consumed it"


def test_pickup_is_one_time():
    broker, private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    _request(broker, "/callback", query=f"code=abc&state={state}")

    auth = {"HTTP_AUTHORIZATION": f"Bearer {BEARER}"}
    first = _request(broker, f"/pickup/{invite}", headers=auth)
    assert first["status"].startswith("200")
    assert json.loads(unseal(private, first["body"]).decode())["refresh_token"]

    second = _request(broker, f"/pickup/{invite}", headers=auth)
    assert second["status"].startswith("404")


def test_non_get_methods_are_rejected():
    broker, _private, _calls = _broker()
    response = _request(broker, "/callback", method="POST")
    assert response["status"].startswith("405")


def test_responses_are_not_cacheable():
    broker, _private, _calls = _broker()
    invite, state, _query = _authorize(broker)
    for response in (_request(broker, f"/start/{invite}"),
                     _request(broker, "/callback",
                              query=f"code=abc&state={state}")):
        assert response["headers"]["Cache-Control"] == "no-store"


# --------------------------------------------------------------------
# No open redirect
# --------------------------------------------------------------------

def test_redirect_uri_comes_from_config_not_the_request():
    broker, _private, calls = _broker()
    invite = broker.create_invite()
    response = _request(
        broker, f"/start/{invite}",
        query="redirect_uri=https://evil.test/steal",
    )
    location = response["headers"]["Location"]

    assert "evil.test" not in location
    assert urllib.parse.quote(
        "https://broker.example.test/callback", safe=""
    ) in location


# --------------------------------------------------------------------
# Store semantics
# --------------------------------------------------------------------

def test_memory_store_expires_and_is_single_use():
    clock = FakeClock()
    store = MemoryStore(clock)
    store.put("k", "v", 10)

    assert store.peek("k") == "v"
    assert store.take("k") == "v"
    assert store.peek("k") is None

    store.put("k2", "v2", 10)
    clock.advance(11)
    assert store.peek("k2") is None


# --------------------------------------------------------------------
# Sealed-box primitives
# --------------------------------------------------------------------

def test_seal_roundtrip():
    private, public = generate_operator_keypair()
    assert unseal(private, seal(public, b"hello")) == b"hello"
    assert unseal(private, seal(public, "text")) == b"text"


def test_sealed_output_differs_every_time():
    _private, public = generate_operator_keypair()
    assert seal(public, b"same") != seal(public, b"same")


def test_tampered_ciphertext_fails_authentication():
    private, public = generate_operator_keypair()
    sealed = bytearray(seal(public, b"payload"))
    sealed[-1] ^= 0x01
    with pytest.raises(SealError):
        unseal(private, bytes(sealed))


def test_sealed_blob_is_bound_to_its_recipient():
    _private_a, public_a = generate_operator_keypair()
    private_b, _public_b = generate_operator_keypair()
    with pytest.raises(SealError):
        unseal(private_b, seal(public_a, b"payload"))


@pytest.mark.parametrize("bad", [b"", b"short", None])
def test_malformed_sealed_input_is_refused(bad):
    private, _public = generate_operator_keypair()
    with pytest.raises(SealError):
        unseal(private, bad)


def test_refuses_to_seal_empty_plaintext():
    _private, public = generate_operator_keypair()
    with pytest.raises(SealError):
        seal(public, b"")


# --------------------------------------------------------------------
# Operator client
# --------------------------------------------------------------------

def test_keygen_writes_an_owner_only_private_key(tmp_path):
    path = str(tmp_path / "keys" / "operator.key")
    public_hex = broker_client.keygen(path)

    assert oct(os.stat(path).st_mode)[-3:] == "600"
    assert oct(os.stat(os.path.dirname(path)).st_mode)[-3:] == "700"
    assert len(bytes.fromhex(public_hex)) == broker_crypto.KEY_BYTES
    # The file holds the private half, which must not equal the public half.
    assert open(path).read().strip() != public_hex


def test_keygen_refuses_to_overwrite_an_existing_key(tmp_path):
    path = str(tmp_path / "operator.key")
    broker_client.keygen(path)
    with pytest.raises(FileExistsError, match="private key"):
        broker_client.keygen(path)


def test_collect_decrypts_locally_and_writes_owner_only(tmp_path):
    private, public = generate_operator_keypair()
    sealed = seal(public, json.dumps({"refresh_token": "1//abc"}).encode())
    out = str(tmp_path / "tokens" / "coach.json")

    broker_client.collect(lambda: sealed, private, out)

    assert oct(os.stat(out).st_mode)[-3:] == "600"
    assert json.load(open(out))["refresh_token"] == "1//abc"


def test_collect_refuses_to_overwrite_an_existing_credential(tmp_path):
    private, public = generate_operator_keypair()
    sealed = seal(public, json.dumps({"refresh_token": "1//abc"}).encode())
    out = tmp_path / "token.json"
    out.write_text("{}")

    with pytest.raises(FileExistsError):
        broker_client.collect(lambda: sealed, private, str(out))
    assert out.read_text() == "{}"


def test_collect_rejects_a_payload_without_a_refresh_token(tmp_path):
    private, public = generate_operator_keypair()
    sealed = seal(public, json.dumps({"access_token": "x"}).encode())
    with pytest.raises(ValueError, match="no refresh token"):
        broker_client.collect(lambda: sealed, private,
                              str(tmp_path / "t.json"))


def test_collect_refuses_an_empty_response(tmp_path):
    private, _public = generate_operator_keypair()
    with pytest.raises(ValueError, match="nothing to collect"):
        broker_client.collect(lambda: b"", private, str(tmp_path / "t.json"))


def test_bearer_is_read_from_the_environment_not_the_command_line():
    args = broker_client.parse_args([
        "collect", "--url", "https://x.test/pickup/i",
        "--private", "k", "--token-out", "t.json",
    ])
    assert args.bearer_env == "BROKER_OPERATOR_BEARER"
    assert not hasattr(args, "bearer")


# --------------------------------------------------------------------
# Nothing here is deployed
# --------------------------------------------------------------------

def test_broker_module_starts_no_listener():
    """The module must be importable and inert: no server, no bind, no
    __main__ that would start one."""
    import ast
    from pathlib import Path

    source = Path("oauth_broker.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "serve_forever", "run_simple", "bind", "listen", "run"
            }, f"oauth_broker.py starts a listener via {node.func.attr}"
    assert 'if __name__ == "__main__"' not in source, (
        "oauth_broker.py has an entry point that could start a server"
    )


def test_no_default_public_endpoint_is_baked_in():
    """collect() takes an injected fetcher; there is no default URL to
    accidentally hit."""
    import inspect

    signature = inspect.signature(broker_client.collect)
    assert list(signature.parameters) == ["fetcher", "private_key",
                                          "token_out"]
    for parameter in signature.parameters.values():
        assert parameter.default is inspect.Parameter.empty


# --------------------------------------------------------------------
# Gaps found by mutation testing, closed here.
# --------------------------------------------------------------------

def test_state_is_consumed_at_the_state_layer_not_only_by_the_invite():
    """B2. A replayed callback is refused twice over: the state is consumed
    and the invite is marked used. Testing only the HTTP outcome cannot tell
    those apart, so assert the state layer directly - otherwise the invite
    check silently becomes the only defence."""
    broker, _private, _calls = _broker()
    _invite, state, _query = _authorize(broker)

    assert broker._take_state(state) is not None
    assert broker._take_state(state) is None, (
        "the state survived its first use; only the invite check would stop "
        "a replay"
    )
    assert broker.states.peek(state) is None


def test_state_lookup_does_not_leak_via_a_prefix():
    broker, _private, _calls = _broker()
    _invite, state, _query = _authorize(broker)

    assert broker._take_state(state[:-1]) is None
    assert broker._take_state(state + "x") is None
    assert broker._take_state("") is None
    assert broker._take_state(None) is None
    # Still usable afterwards: near misses must not consume it.
    assert broker._take_state(state) is not None


def _source(filename):
    from pathlib import Path
    return Path(filename).read_text(encoding="utf-8")


def test_secret_comparisons_are_constant_time():
    """B3/B12. `==` and compare_digest behave identically, so no functional
    test can separate them - only the source can. Both the CSRF state and the
    operator bearer are attacker-supplied and compared against a secret."""
    import ast

    tree = ast.parse(_source("oauth_broker.py"))
    checked = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef)
                and node.name in {"_take_state", "bearer_matches"}):
            continue

        # Look for a real call node, not the word "compare_digest" appearing
        # anywhere in the function. A previous version of this test matched
        # the unparsed source, and the function's own docstring - which
        # explains why compare_digest is used - satisfied it even after the
        # call itself was deleted. Prose must not be able to vouch for code.
        calls = [
            child for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and (
                (isinstance(child.func, ast.Attribute)
                 and child.func.attr == "compare_digest")
                or (isinstance(child.func, ast.Name)
                    and child.func.id == "compare_digest")
            )
        ]
        assert calls, (
            f"{node.name} does not actually call hmac.compare_digest; a "
            "mention in a docstring or comment is not a comparison"
        )
        checked.add(node.name)

    assert checked == {"_take_state", "bearer_matches"}, (
        f"expected both secret comparisons, found {sorted(checked)}"
    )


def test_https_is_required_by_default_and_enforced():
    """B16, re-run with the real source text."""
    broker, _private, _calls = _broker()
    assert broker.config.require_https is True

    for path in ("/callback", "/start/x", "/pickup/x"):
        response = _request(broker, path, scheme="http")
        assert response["status"].startswith("400"), path
        assert "HTTPS" in response["body"].decode()


def test_operator_private_key_is_created_owner_only_and_exclusively(tmp_path):
    """B19. The private key is the one secret that must never widen."""
    import ast

    tree = ast.parse(_source("broker_client.py"))

    # Scoped per function. A file-wide scan would let one correct os.open
    # vouch for a different, mutated one - and the trailing chmod hides the
    # runtime effect, so only the creation flags reveal it.
    for function_name in ("keygen", "collect"):
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        opens = [
            ast.unparse(node) for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and "O_CREAT" in ast.unparse(node)
        ]
        assert opens, f"{function_name} does not create its file explicitly"
        for call in opens:
            assert "O_EXCL" in call, (
                f"{function_name} must create exclusively, not clobber"
            )
            assert "384" in call or "0o600" in call, (
                f"{function_name} must create owner-only, not chmod after"
            )

    path = str(tmp_path / "operator.key")
    broker_client.keygen(path)
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_take_is_a_single_removal_not_a_read_then_pop():
    """A threaded WSGI server can run two callbacks concurrently. If take()
    reads before it removes, both callers see a live state and both proceed
    to the token exchange - the single-use rule silently stops holding.

    Asserted on the source because a deterministic unit test cannot reliably
    interleave two threads at the exact window."""
    import ast

    tree = ast.parse(_source("oauth_broker.py"))
    take = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "take"
    )
    body = ast.unparse(take)

    assert "pop" in body, "take() must remove the entry"
    assert "self.peek" not in body, (
        "take() delegates to peek(), which reads before removing; two "
        "concurrent callers could both observe the same live state"
    )


def test_concurrent_takes_yield_the_value_once():
    import threading

    store = MemoryStore(FakeClock())
    store.put("k", "only-once", 100)
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(store.take("k"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count("only-once") == 1, (
        f"the value was handed out {results.count('only-once')} times"
    )


# --------------------------------------------------------------------
# Deployment surfaces: seeded invites, health check, proxy scheme
# --------------------------------------------------------------------

def _seeded_broker(invite_ids):
    private, public = generate_operator_keypair()
    config = BrokerConfig(
        client_id="client-id.apps.googleusercontent.com",
        client_secret=CLIENT_SECRET,
        redirect_uri="https://broker.example.test/callback",
        operator_public_key=public,
        operator_bearer=BEARER,
        seed_invites=invite_ids,
    )
    return OAuthBroker(config, exchange_fn=lambda e, p: {
        "refresh_token": "1//seeded"}, clock=FakeClock()), private


def test_invites_can_be_seeded_from_configuration():
    """Deployment path: the operator mints offline and sets an env var."""
    invite = broker_client.mint_invite()
    broker, _private = _seeded_broker([invite])

    response = _request(broker, f"/start/{invite}")
    assert response["status"].startswith("302")


def test_seeded_invites_ignore_blank_entries():
    """A trailing comma in the env var must not create an empty invite that
    /start/ would then match on an empty path segment."""
    broker, _private = _seeded_broker(["", "   ", broker_client.mint_invite()])

    assert len(broker.config.seed_invites) == 1
    assert _request(broker, "/start/")["status"].startswith("404")


def test_short_invite_ids_are_refused_at_configuration_time():
    _private, public = generate_operator_keypair()
    with pytest.raises(BrokerConfigError, match="at least 16"):
        BrokerConfig(
            client_id="c", client_secret=CLIENT_SECRET,
            redirect_uri="https://b.example.test/callback",
            operator_public_key=public, operator_bearer=BEARER,
            seed_invites=["short"],
        )


def test_minted_invites_are_unique_and_long():
    minted = {broker_client.mint_invite() for _ in range(50)}
    assert len(minted) == 50
    assert all(len(value) >= 16 for value in minted)


def test_no_http_endpoint_creates_an_invite():
    """Invite creation must stay off the network entirely."""
    broker, _private = _seeded_broker([broker_client.mint_invite()])
    before = len(broker.invites)

    for path in ("/invite", "/invites", "/admin", "/create", "/start/",
                 "/callback", "/pickup/x"):
        _request(broker, path, headers={"HTTP_AUTHORIZATION": f"Bearer {BEARER}"})
    assert len(broker.invites) == before


def test_healthz_answers_without_https_and_reveals_nothing():
    """A platform probe reaches the app over the internal network, so the
    health check must answer before the scheme check or the service is
    marked permanently unhealthy."""
    broker, _private = _seeded_broker([broker_client.mint_invite()])

    response = _request(broker, "/healthz", scheme="http")
    assert response["status"].startswith("200")

    body = response["body"].decode()
    assert body == "ok"
    assert CLIENT_SECRET not in body and BEARER not in body


def test_forwarded_proto_is_honoured_behind_a_proxy():
    """Behind a hosting proxy wsgi.url_scheme is http; without honouring
    X-Forwarded-Proto every real request would be rejected."""
    broker, _private = _seeded_broker([broker_client.mint_invite()])
    invite = broker.config.seed_invites[0]

    proxied = _request(broker, f"/start/{invite}", scheme="http",
                       headers={"HTTP_X_FORWARDED_PROTO": "https"})
    assert proxied["status"].startswith("302")

    direct = _request(broker, f"/start/{invite}", scheme="http")
    assert direct["status"].startswith("400")


def test_forwarded_proto_takes_the_first_hop():
    broker, _private = _seeded_broker([broker_client.mint_invite()])
    invite = broker.config.seed_invites[0]

    response = _request(broker, f"/start/{invite}", scheme="http",
                        headers={"HTTP_X_FORWARDED_PROTO": "https, http"})
    assert response["status"].startswith("302")


# --------------------------------------------------------------------
# WSGI entry point
# --------------------------------------------------------------------

def test_wsgi_module_builds_from_environment():
    import broker_wsgi

    _private, public = generate_operator_keypair()
    env = {
        "BROKER_CLIENT_ID": "id.apps.googleusercontent.com",
        "BROKER_CLIENT_SECRET": CLIENT_SECRET,
        "BROKER_REDIRECT_URI": "https://b.example.test/callback",
        "BROKER_OPERATOR_PUBLIC_KEY": public.hex(),
        "BROKER_OPERATOR_BEARER": BEARER,
        "BROKER_INVITE_IDS": broker_client.mint_invite(),
    }
    app = broker_wsgi.build_application(env)
    assert isinstance(app, OAuthBroker)
    assert len(app.invites) == 1


def test_wsgi_module_refuses_an_unsafe_environment():
    """A missing secret must fail the deploy, not serve a broken broker."""
    import broker_wsgi

    with pytest.raises(BrokerConfigError):
        broker_wsgi.build_application({"BROKER_CLIENT_ID": "only-this"})


def test_wsgi_import_does_not_require_configuration():
    """Importing must not construct anything: a build step with no secrets
    present has to be able to import this module."""
    import importlib

    import broker_wsgi
    importlib.reload(broker_wsgi)
    assert broker_wsgi._broker is None


def test_wsgi_module_starts_no_listener():
    import ast

    tree = ast.parse(_source("broker_wsgi.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"serve_forever", "bind", "listen",
                                          "run", "run_simple"}
    assert 'if __name__ == "__main__"' not in _source("broker_wsgi.py")


# --------------------------------------------------------------------
# Deployment configuration must not contradict the code's assumptions
# --------------------------------------------------------------------

def test_deployment_config_pins_a_single_instance_and_worker():
    """The in-memory stores are only correct in one process. If the config
    ever scales out, sign-ins break and the single-use guarantees hold only
    per instance - so the config is asserted, not just commented."""
    from pathlib import Path

    render = Path("render.yaml").read_text(encoding="utf-8")
    assert "numInstances: 1" in render
    assert "--workers 1" in render

    procfile = Path("Procfile").read_text(encoding="utf-8")
    assert "--workers 1" in procfile
    assert "broker_wsgi:application" in procfile


def test_no_secret_value_is_committed_in_deployment_config():
    from pathlib import Path

    for name in ("render.yaml", "Procfile", "broker.env.example"):
        text = Path(name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            for variable in ("BROKER_CLIENT_SECRET", "BROKER_OPERATOR_BEARER",
                             "BROKER_OPERATOR_PUBLIC_KEY", "BROKER_INVITE_IDS"):
                if variable in line and "=" in line:
                    assert line.strip().endswith("="), (
                        f"{name} appears to carry a value for {variable}"
                    )
                if variable in line and "sync:" in text:
                    assert "sync: false" in text


def test_env_example_documents_every_required_variable():
    from pathlib import Path

    text = Path("broker.env.example").read_text(encoding="utf-8")
    for variable in ("BROKER_CLIENT_ID", "BROKER_CLIENT_SECRET",
                     "BROKER_REDIRECT_URI", "BROKER_OPERATOR_PUBLIC_KEY",
                     "BROKER_OPERATOR_BEARER", "BROKER_INVITE_IDS"):
        assert variable in text, f"{variable} is undocumented"


def test_operator_private_key_cannot_be_committed():
    """The private key is the one artifact whose loss is unrecoverable and
    whose exposure defeats the entire design. keygen's natural invocation
    writes it into the repository directory, so ignoring it is not optional."""
    from pathlib import Path

    ignored = Path(".gitignore").read_text(encoding="utf-8")
    assert "*.key" in ignored
    assert "broker-operator" in ignored
    # The example must stay committed; a filled-in copy must not.
    assert "broker.env" in ignored
    assert "!broker.env.example" in ignored


# --------------------------------------------------------------------
# Environment parsing must diagnose the real cause.
# --------------------------------------------------------------------

_GOOD_HEX = "bb" * 32


def _env(**overrides):
    env = {
        "BROKER_CLIENT_ID": "id.apps.googleusercontent.com",
        "BROKER_CLIENT_SECRET": CLIENT_SECRET,
        "BROKER_REDIRECT_URI": "https://b.example.test/callback",
        "BROKER_OPERATOR_PUBLIC_KEY": _GOOD_HEX,
        "BROKER_OPERATOR_BEARER": BEARER,
        "BROKER_INVITE_IDS": "",
    }
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


def test_a_valid_hex_public_key_is_accepted():
    assert BrokerConfig.from_environment(_env()).operator_public_key == \
        bytes.fromhex(_GOOD_HEX)


@pytest.mark.parametrize("value", [None, "", "   ", '""'])
def test_missing_public_key_says_it_is_missing(value):
    """bytes.fromhex("") returns b"" without raising, so an unset variable
    used to reach the length check and be reported as a format problem -
    sending the reader to inspect a value that was correct."""
    with pytest.raises(BrokerConfigError, match="is not set"):
        BrokerConfig.from_environment(_env(BROKER_OPERATOR_PUBLIC_KEY=value))


@pytest.mark.parametrize("value", [
    '"' + _GOOD_HEX + '"',
    "'" + _GOOD_HEX + "'",
    "0x" + _GOOD_HEX,
    "0X" + _GOOD_HEX,
    "  " + _GOOD_HEX + "  ",
    _GOOD_HEX + "\n",
])
def test_paste_artifacts_are_tolerated(value):
    """Quotes, a 0x prefix, and stray whitespace are what a value picks up
    on its way through a hosting dashboard."""
    config = BrokerConfig.from_environment(
        _env(BROKER_OPERATOR_PUBLIC_KEY=value)
    )
    assert config.operator_public_key == bytes.fromhex(_GOOD_HEX)


@pytest.mark.parametrize("value,expected", [
    (_GOOD_HEX[:-1], "must be hex"),
    ("zz" * 32, "must be hex"),
    ("bb" * 16, "exactly 64 hex characters"),
    ("bb" * 64, "exactly 64 hex characters"),
])
def test_malformed_public_keys_report_the_observed_length(value, expected):
    with pytest.raises(BrokerConfigError, match=expected):
        BrokerConfig.from_environment(
            _env(BROKER_OPERATOR_PUBLIC_KEY=value)
        )


def test_env_errors_never_echo_a_secret():
    """An error about one variable must not print the value of another."""
    for override in ({"BROKER_OPERATOR_PUBLIC_KEY": None},
                     {"BROKER_OPERATOR_PUBLIC_KEY": "nothex" * 11}):
        try:
            BrokerConfig.from_environment(_env(**override))
        except BrokerConfigError as exc:
            assert CLIENT_SECRET not in str(exc)
            assert BEARER not in str(exc)


def test_ttl_constants_are_documented_as_upper_bounds():
    """The 24-hour TTLs were stated in three places as if they were a
    guarantee. They are not: both stores are in process memory, and the
    deployed free-plan instance spins down when idle, which wipes them. A
    pickup lost that way returns 404 - indistinguishable from one already
    collected, which is the misleading part."""
    source = _source("oauth_broker.py")
    ttl_block = source[source.index("INVITE_TTL_SECONDS") - 400:
                       source.index("INVITE_TTL_SECONDS") + 80]

    assert "spin" in ttl_block.lower(), (
        "the TTL constants must record that they are upper bounds, not "
        "guarantees, or the next reader will trust them again"
    )


def test_documentation_does_not_promise_a_24_hour_pickup_window():
    """Regression for a false claim that was in the README, the mint-invite
    output, and implicitly in the constants."""
    from pathlib import Path

    readme = Path("README.md").read_text(encoding="utf-8")
    client = Path("broker_client.py").read_text(encoding="utf-8")

    # The only surviving mention in the README is the heading that denies it.
    mentions = [line for line in readme.splitlines()
                if "24 hour" in line or "24h" in line]
    assert all("not 24 hours" in line for line in mentions), (
        f"README still promises a 24-hour window: {mentions}"
    )
    assert "sits for up to 24 hours awaiting pickup" not in readme
    assert "single use and expires in 24 hours" not in client
