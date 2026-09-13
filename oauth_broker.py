"""Hosted OAuth callback broker: let an account owner authorize Gmail from
their own device, without the operator's machine being involved.

DEPLOYED as a test service at https://email-scanner-hhma.onrender.com, on
Render's free plan. Hosting configuration is in `render.yaml`, `Procfile`,
`broker-requirements.txt`, and `broker.env.example`. It has been run end to
end with a personal test account. It has never produced a credential for the
account owner's mailbox, and it doesn't bypass the Workspace
admin_policy_enforced block, which applies here exactly as it does to the
desktop flow.

Flow
----
1.  The operator creates a single-use invite out of band and sends the owner
    a /start/<invite> link.
2.  The owner opens it. The broker mints a CSRF `state` and a PKCE verifier,
    stores both server-side, and redirects to Google. Nothing secret is in
    that redirect.
3.  Google sends the owner back to /callback with a code and the state. The
    broker validates the state (single-use, expiring, constant-time), then
    exchanges the code for tokens SERVER-SIDE using the client secret and the
    PKCE verifier.
4.  The refresh token is immediately sealed to the operator's X25519 public
    key and only the ciphertext is stored. The owner sees a plain success
    page containing no token, no code, and no secret.
5.  The operator fetches the ciphertext once from /pickup/<invite> with a
    bearer credential and decrypts it locally.

The token therefore passes through Google and this broker only, and the
broker never holds a form of it that it could use.

Security properties this file is responsible for
------------------------------------------------
* `state` is 256 bits of os.urandom, single-use, TTL-bounded, and compared
  with hmac.compare_digest.
* PKCE S256 is always used, so an intercepted code is not redeemable.
* The client secret is read from the environment and never appears in a
  response, a redirect, a log line, or an error page.
* redirect_uri is fixed by configuration and never taken from a request, so
  there is no open redirect.
* Tokens and codes are never logged and never placed in a URL the broker
  builds.
* Only sealed ciphertext is persisted. Plaintext exists in one local variable
  for the duration of the exchange.

Known limits
------------
* The stores are in-memory, so this is correct for a single worker process
  only. Multiple gunicorn workers would need shared storage (Redis, or a
  small database) with the same single-use semantics. `render.yaml` pins
  numInstances: 1 and --workers 1.
* On Render's free plan an idle spin-down wipes those stores. Pending states
  and uncollected sealed pickups are destroyed, and both then look identical
  to "already used". Treat the flow as one continuous sitting; there is no
  24-hour pickup window on this plan. See the README section "On the free
  plan the real window is one sitting, not 24 hours".
* There is no rate limiting here; put that in front of it.
* HTTPS is required and enforced by `require_https`, but TLS termination is
  the deployment's job.
"""
import hmac
import html
import json
import logging
import os
import secrets
import time
import urllib.parse
from base64 import urlsafe_b64encode
from hashlib import sha256

import broker_crypto

logger = logging.getLogger(__name__)

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# Matches the desktop flow's least-privilege choice.
DEFAULT_SCOPES = ("https://www.googleapis.com/auth/gmail.modify",)

STATE_BYTES = 32          # 256 bits
STATE_TTL_SECONDS = 600   # 10 minutes to complete a sign-in
# Upper bounds, not guarantees. Both stores are in process memory, so on a
# host that spins an idle instance down (Render's free plan does) the real
# lifetime is "until the next spin-down", which can be far shorter. A pickup
# lost this way returns 404 - indistinguishable from one already collected.
INVITE_TTL_SECONDS = 86400
PICKUP_TTL_SECONDS = 86400

# Never emit these into a response body, header, or log line.
SECRET_FIELD_NAMES = frozenset({
    "client_secret", "code", "access_token", "refresh_token", "id_token",
    "code_verifier",
})


class BrokerConfigError(RuntimeError):
    """Raised when the broker is not safely configured."""


def _b64url(raw):
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class BrokerConfig:
    """Broker configuration. The client secret is read from the environment
    and is never accepted from a request or written to a response."""

    def __init__(self, client_id, client_secret, redirect_uri,
                 operator_public_key, operator_bearer,
                 scopes=DEFAULT_SCOPES, require_https=True,
                 seed_invites=()):
        if not client_id:
            raise BrokerConfigError("client_id is required")
        if not client_secret:
            raise BrokerConfigError("client_secret is required")
        if not redirect_uri:
            raise BrokerConfigError("redirect_uri is required")
        if require_https and not redirect_uri.startswith("https://"):
            raise BrokerConfigError(
                "redirect_uri must be https; an OAuth code must never cross "
                "a plaintext connection"
            )
        if len(operator_public_key or b"") != broker_crypto.KEY_BYTES:
            raise BrokerConfigError(
                "operator_public_key must be 32 raw bytes"
            )
        if len(operator_bearer or "") < 32:
            raise BrokerConfigError(
                "operator_bearer must be at least 32 characters"
            )
        self.client_id = client_id
        self._client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.operator_public_key = bytes(operator_public_key)
        self._operator_bearer = operator_bearer
        self.scopes = tuple(scopes)
        self.require_https = require_https
        # Invite ids are minted OFFLINE by the operator and supplied here.
        # Nothing reachable over the network can create one, and because the
        # stores are per-process, a shell session on a hosted instance could
        # not have seeded the web worker anyway.
        self.seed_invites = tuple(
            value.strip() for value in seed_invites if value and value.strip()
        )
        for invite_id in self.seed_invites:
            if len(invite_id) < 16:
                raise BrokerConfigError(
                    "seeded invite ids must be at least 16 characters; mint "
                    "them with: python broker_client.py mint-invite"
                )

    @property
    def client_secret(self):
        return self._client_secret

    def bearer_matches(self, presented):
        return hmac.compare_digest(self._operator_bearer, presented or "")

    @staticmethod
    def _clean_env_value(raw):
        """Strip artifacts a value picks up on its way through a dashboard.

        Whitespace, a trailing newline, and surrounding quotes are common
        when pasting into a hosting provider's environment editor, and some
        editors store the quotes literally.
        """
        value = (raw or "").strip()
        for quote in ('"', "'"):
            if len(value) >= 2 and value.startswith(quote) and \
                    value.endswith(quote):
                value = value[1:-1].strip()
        return value

    @classmethod
    def from_environment(cls, env=None):
        env = env if env is not None else os.environ

        public_hex = cls._clean_env_value(
            env.get("BROKER_OPERATOR_PUBLIC_KEY", "")
        )
        if public_hex.lower().startswith("0x"):
            public_hex = public_hex[2:]

        # An unset variable must not be reported as a format problem.
        # bytes.fromhex("") returns b"" without raising, so an empty value
        # would otherwise sail past the hex check and fail the length check
        # with a message that sends you looking at the wrong thing.
        if not public_hex:
            raise BrokerConfigError(
                "BROKER_OPERATOR_PUBLIC_KEY is not set (or is empty). It is "
                "the 64-character hex PUBLIC key printed by: "
                "python broker_client.py keygen --private-out broker-operator.key"
            )
        try:
            public_key = bytes.fromhex(public_hex)
        except ValueError as exc:
            raise BrokerConfigError(
                "BROKER_OPERATOR_PUBLIC_KEY must be hex: expected 64 "
                f"hex characters, got {len(public_hex)} characters that are "
                "not valid hex"
            ) from exc
        if len(public_key) != broker_crypto.KEY_BYTES:
            raise BrokerConfigError(
                "BROKER_OPERATOR_PUBLIC_KEY must be exactly 64 hex "
                f"characters (32 bytes); got {len(public_hex)} characters "
                f"decoding to {len(public_key)} bytes"
            )
        return cls(
            client_id=env.get("BROKER_CLIENT_ID", ""),
            client_secret=env.get("BROKER_CLIENT_SECRET", ""),
            redirect_uri=env.get("BROKER_REDIRECT_URI", ""),
            operator_public_key=public_key,
            operator_bearer=env.get("BROKER_OPERATOR_BEARER", ""),
            seed_invites=env.get("BROKER_INVITE_IDS", "").split(","),
        )


class MemoryStore:
    """Single-use, TTL-bounded storage.

    In-memory, so correct for one worker process only. Deployment with more
    than one worker must swap this for shared storage with identical
    single-use semantics.
    """

    def __init__(self, clock=time.monotonic):
        self._items = {}
        self._clock = clock

    def put(self, key, value, ttl):
        self._items[key] = (value, self._clock() + ttl)

    def peek(self, key):
        entry = self._items.get(key)
        if entry is None:
            return None
        value, expires = entry
        if self._clock() >= expires:
            self._items.pop(key, None)
            return None
        return value

    def take(self, key):
        """Remove and return in one step, so two concurrent callers cannot
        both receive the same value.

        dict.pop is a single bytecode-level operation under the GIL, so it
        is the removal that decides the winner. Reading first and popping
        second would let two threads in a threaded WSGI server both observe
        a live state before either consumed it - which is exactly the replay
        the single-use rule exists to stop.
        """
        entry = self._items.pop(key, None)
        if entry is None:
            return None
        value, expires = entry
        if self._clock() >= expires:
            return None
        return value

    def discard(self, key):
        self._items.pop(key, None)

    def __len__(self):
        return len(self._items)


def _exchange_with_requests(token_endpoint, payload):
    import requests

    response = requests.post(token_endpoint, data=payload, timeout=30)
    if response.status_code != 200:
        # Deliberately does not include the body: it can echo the code.
        raise RuntimeError(
            f"token exchange failed with status {response.status_code}"
        )
    return response.json()


class OAuthBroker:
    """WSGI application implementing the three endpoints."""

    def __init__(self, config, exchange_fn=_exchange_with_requests,
                 clock=time.monotonic):
        self.config = config
        self._exchange = exchange_fn
        self._clock = clock
        self.invites = MemoryStore(clock)
        self.states = MemoryStore(clock)
        self.pickups = MemoryStore(clock)
        for invite_id in getattr(config, "seed_invites", ()):
            self.invites.put(invite_id, {"label": "seeded", "used": False},
                             INVITE_TTL_SECONDS)

    # -- operator-side helpers (not HTTP endpoints) ------------------

    def create_invite(self, label="account owner"):
        """Mint a single-use invite id in this process.

        Not reachable over HTTP, and on a hosted instance not reachable from
        a shell either, since the stores live in the web worker's memory.
        Deployment seeds invites through BROKER_INVITE_IDS instead; this
        stays for local runs and tests.
        """
        invite_id = secrets.token_urlsafe(24)
        self.invites.put(invite_id, {"label": label, "used": False},
                         INVITE_TTL_SECONDS)
        return invite_id

    # -- routing -----------------------------------------------------

    @staticmethod
    def _scheme(environ):
        """The scheme the CLIENT used, not the one the proxy used to reach us.

        Behind a hosting proxy the app is normally spoken to over plain HTTP
        on the internal network, so wsgi.url_scheme alone would reject every
        request. X-Forwarded-Proto carries what the browser actually used.

        A client that could reach this app directly could forge that header,
        but gains nothing by it: Google will only redirect to the https
        redirect_uri registered on the OAuth client, so no code reaches an
        http endpoint regardless. This check is defence in depth against a
        misconfigured deployment, not the thing keeping codes off the wire.
        """
        forwarded = environ.get("HTTP_X_FORWARDED_PROTO", "")
        if forwarded:
            return forwarded.split(",")[0].strip().lower()
        return environ.get("wsgi.url_scheme", "")

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")

        if method != "GET":
            return self._respond(start_response, "405 Method Not Allowed",
                                 "Method not allowed.")

        # Answered before the scheme check so a platform health probe on the
        # internal network cannot mark the service unhealthy. It reveals
        # nothing: a fixed string, no configuration, no counts.
        if path == "/healthz":
            return self._respond(start_response, "200 OK", "ok")

        if self.config.require_https and self._scheme(environ) != "https":
            return self._respond(start_response, "400 Bad Request",
                                 "This endpoint requires HTTPS.")

        if path == "/":
            return self._public_page(
                start_response,
                "Email Scanner",
                """
                <p class="lede">An inbox assistant for one connected Google
                account.</p>
                <p>Email Scanner organizes Gmail with labels and creates
                reply drafts for review. It never sends email automatically.</p>
                <p><a href="/privacy">Privacy policy</a>
                <span aria-hidden="true">&middot;</span>
                <a href="/terms">Terms of service</a></p>
                """,
            )
        if path == "/privacy":
            return self._public_page(
                start_response,
                "Privacy policy",
                """
                <p class="updated">Last updated September 9, 2026</p>
                <h2>What the app accesses</h2>
                <p>After you give permission, Email Scanner accesses the
                Gmail messages needed to apply labels and create reply
                drafts. It also uses the Google account email address to
                identify the one connected account.</p>
                <h2>How information is used</h2>
                <p>Message content is processed only to classify email and
                generate a proposed reply. Content needed for those tasks is
                sent to the configured Google Gemini service, and the
                resulting labels and drafts are written back to Gmail. The
                app does not send email automatically, sell personal data, or
                use Gmail data for advertising.</p>
                <h2>Storage and security</h2>
                <p>The Gmail refresh credential is encrypted at rest on the
                operator-managed server. Message bodies are processed
                transiently rather than intentionally stored by the website.
                The app may retain settings, opaque message identifiers, run
                counts, and limited error metadata needed to prevent duplicate
                work and operate the service.</p>
                <h2>Control and deletion</h2>
                <p>Only one Google account can be connected at a time. The
                account owner can disconnect it from the dashboard, which
                revokes and removes the app's stored Gmail credential and
                stops future runs. Labels and drafts already created in Gmail
                remain under the account owner's control.</p>
                <h2>Google API data</h2>
                <p>The app's use and transfer of information received from
                Google APIs follows the Google API Services User Data Policy,
                including its Limited Use requirements.</p>
                <h2>Contact</h2>
                <p>For privacy questions, use the developer support address
                shown on the Google consent screen.</p>
                """,
            )
        if path == "/terms":
            return self._public_page(
                start_response,
                "Terms of service",
                """
                <p class="updated">Last updated September 9, 2026</p>
                <p>Email Scanner is an inbox assistant. Use it only with a
                Google account you own or are authorized to manage.</p>
                <p>The app applies labels and creates draft replies; it does
                not send messages automatically. You are responsible for
                reviewing every draft and for changes made in your mailbox.</p>
                <p>The service is provided as-is and may be changed, paused,
                or discontinued. Disconnect the Google account from the
                dashboard to stop future access.</p>
                """,
            )
        if path.startswith("/start/"):
            return self._start(environ, start_response,
                               path[len("/start/"):])
        if path == "/callback":
            return self._callback(environ, start_response)
        if path.startswith("/pickup/"):
            return self._pickup(environ, start_response,
                                path[len("/pickup/"):])
        return self._respond(start_response, "404 Not Found", "Not found.")

    # -- endpoints ---------------------------------------------------

    def _start(self, environ, start_response, invite_id):
        invite = self.invites.peek(invite_id)
        if invite is None or invite.get("used"):
            # Same message either way: an attacker must not learn whether an
            # invite id exists.
            return self._respond(start_response, "404 Not Found",
                                 "This link is not valid or has expired.")

        state = secrets.token_urlsafe(STATE_BYTES)
        verifier = secrets.token_urlsafe(64)
        challenge = _b64url(sha256(verifier.encode("ascii")).digest())

        self.states.put(state, {"state": state, "invite_id": invite_id,
                                "verifier": verifier}, STATE_TTL_SECONDS)

        query = urllib.parse.urlencode({
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
        })
        location = f"{GOOGLE_AUTH_ENDPOINT}?{query}"
        start_response("302 Found", [
            ("Location", location),
            ("Cache-Control", "no-store"),
            ("Content-Length", "0"),
        ])
        return [b""]

    def _callback(self, environ, start_response):
        params = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        presented_state = (params.get("state") or [""])[0]
        code = (params.get("code") or [""])[0]

        if params.get("error"):
            return self._respond(start_response, "400 Bad Request",
                                 "Sign-in was cancelled or denied.")

        # Single-use: taken before any other work, so a replayed callback
        # cannot reach the exchange even concurrently.
        record = self._take_state(presented_state)
        if record is None or not code:
            return self._respond(start_response, "400 Bad Request",
                                 "This sign-in link is not valid or has "
                                 "already been used. Ask for a new one.")

        invite = self.invites.peek(record["invite_id"])
        if invite is None or invite.get("used"):
            return self._respond(start_response, "400 Bad Request",
                                 "This invitation has already been used.")

        payload = {
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": record["verifier"],
        }
        try:
            tokens = self._exchange(GOOGLE_TOKEN_ENDPOINT, payload)
        except Exception:
            # No exception detail is surfaced: it can contain the code.
            logger.warning("Token exchange failed for an invite")
            return self._respond(start_response, "502 Bad Gateway",
                                 "Could not complete sign-in. Please ask for "
                                 "a new link.")
        finally:
            payload = None

        refresh_token = (tokens or {}).get("refresh_token")
        if not refresh_token:
            logger.warning("Exchange returned no refresh token")
            return self._respond(start_response, "400 Bad Request",
                                 "Sign-in did not return a durable "
                                 "credential. Please ask for a new link.")

        sealed = broker_crypto.seal(
            self.config.operator_public_key,
            json.dumps({
                "refresh_token": refresh_token,
                "scope": (tokens or {}).get("scope", ""),
                "token_type": (tokens or {}).get("token_type", ""),
            }).encode("utf-8"),
        )
        # Only ciphertext is retained. Drop every plaintext reference.
        tokens = None
        refresh_token = None

        self.pickups.put(record["invite_id"], sealed, PICKUP_TTL_SECONDS)
        self.invites.put(record["invite_id"],
                         {"label": invite.get("label"), "used": True},
                         INVITE_TTL_SECONDS)

        return self._respond(
            start_response, "200 OK",
            "Thanks - your account is connected. You can close this tab. "
            "Nothing was sent from your account, and no message was read "
            "during sign-in.",
        )

    def _pickup(self, environ, start_response, invite_id):
        header = environ.get("HTTP_AUTHORIZATION", "")
        presented = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        if not self.config.bearer_matches(presented):
            return self._respond(start_response, "401 Unauthorized",
                                 "Unauthorized.")

        sealed = self.pickups.take(invite_id)
        if sealed is None:
            return self._respond(start_response, "404 Not Found",
                                 "Nothing to collect.")
        start_response("200 OK", [
            ("Content-Type", "application/octet-stream"),
            ("Cache-Control", "no-store"),
            ("Content-Length", str(len(sealed))),
        ])
        return [sealed]

    # -- helpers -----------------------------------------------------

    def _take_state(self, presented):
        """Consume the pending state matching `presented`, or return None.

        A direct dict lookup rather than a scan. The state is 256 bits of
        os.urandom, so it cannot be guessed, and lookup cost no longer grows
        with the number of sign-ins in flight.

        The compare_digest below confirms the stored value in constant time.
        With a direct-key lookup that confirmation is a second opinion rather
        than the primary defence - it becomes load-bearing only if the store
        is ever changed to key by a hash or prefix, which is exactly the kind
        of change that would otherwise silently weaken this.
        """
        if not presented:
            return None
        record = self.states.take(presented)
        if record is None:
            return None
        if not hmac.compare_digest(record.get("state", ""), presented):
            return None
        return record

    @staticmethod
    def _respond(start_response, status, message):
        body = message.encode("utf-8")
        start_response(status, [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    @staticmethod
    def _public_page(start_response, title, content):
        safe_title = html.escape(title)
        body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title} | Email Scanner</title>
  <style>
    :root {{ color-scheme: light; font-family: ui-sans-serif, system-ui,
      -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ background: #f6f7f9; color: #18202b; margin: 0; }}
    main {{ background: white; border: 1px solid #e1e5ea; border-radius: 16px;
      box-shadow: 0 12px 34px rgba(24,32,43,.08); margin: 8vh auto;
      max-width: 680px; padding: clamp(24px, 5vw, 52px); width: 78%; }}
    h1 {{ font-size: clamp(2rem, 6vw, 3.25rem); letter-spacing: -.04em;
      line-height: 1; margin: 0 0 1.25rem; }}
    h2 {{ font-size: 1.05rem; margin: 2rem 0 .45rem; }}
    p {{ line-height: 1.65; }}
    .lede {{ color: #405065; font-size: 1.2rem; }}
    .updated {{ color: #68778a; font-size: .9rem; }}
    a {{ color: #1769aa; }}
  </style>
</head>
<body><main><h1>{safe_title}</h1>{content}</main></body>
</html>""".encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Content-Security-Policy",
             "default-src 'none'; style-src 'unsafe-inline'; "
             "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
