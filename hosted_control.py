"""Authenticated Gmail connect and disconnect operations for the dashboard.

OAuth state and PKCE material live only in this single worker's memory and
expire after ten minutes. The callback consumes state before exchanging its
code, then encrypts the refresh token with Cloud KMS before publishing the
connection. Disconnect attempts Google revocation and always destroys the
local encrypted credential while archiving non-credential account records.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

import connection
import connection_archive
import connection_tokens
from connect_account import build_provider, connect_token_document
from gmail_auth import SCOPES
from gmail_common import normalize_address
from gmail_retry import gmail_execute


OAUTH_TTL_SECONDS = 600
GOOGLE_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke"


class HostedControlError(RuntimeError):
    """A user-safe control error that never contains token or OAuth code."""


class HostedControlConfig:
    def __init__(self, state_root, credentials_path, kms_key, redirect_uri):
        self.state_root = Path(state_root)
        self.credentials_path = Path(credentials_path)
        self.kms_key = str(kms_key or "").strip()
        self.redirect_uri = str(redirect_uri or "").strip()
        if not self.credentials_path.is_file():
            raise HostedControlError("OAuth client configuration is unavailable")
        if not self.kms_key:
            raise HostedControlError("Cloud KMS configuration is unavailable")
        parsed = urllib.parse.urlsplit(self.redirect_uri)
        loopback_http = (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        )
        if parsed.scheme != "https" and not loopback_http:
            raise HostedControlError(
                "OAuth callback must use HTTPS or a loopback address"
            )
        if parsed.path != "/oauth/callback" or parsed.query or parsed.fragment:
            raise HostedControlError("OAuth callback address is invalid")

    @classmethod
    def from_environment(cls, env, state_root):
        return cls(
            state_root,
            env.get("GMAIL_CREDENTIALS_PATH", ""),
            env.get("CONNECTION_KMS_KEY", ""),
            env.get("DASHBOARD_OAUTH_REDIRECT_URI", ""),
        )


def revoke_google_token(token_document):
    """Revoke the refresh grant without putting the token in the URL."""
    token = (token_document or {}).get("refresh_token")
    if not isinstance(token, str) or not token:
        return False
    body = urllib.parse.urlencode({"token": token}).encode("ascii")
    request = urllib.request.Request(
        GOOGLE_REVOCATION_ENDPOINT,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status == 200


class HostedControl:
    def __init__(self, config, *, flow_factory=None, service_builder=build,
                 provider_builder=build_provider, revoker=revoke_google_token,
                 clock=time.monotonic):
        self.config = config
        self._flow_factory = flow_factory or Flow.from_client_secrets_file
        self._service_builder = service_builder
        self._provider_builder = provider_builder
        self._revoker = revoker
        self._clock = clock
        self._states = {}
        self._state_lock = threading.Lock()

    def _flow(self, **kwargs):
        return self._flow_factory(
            str(self.config.credentials_path), SCOPES,
            redirect_uri=self.config.redirect_uri, **kwargs,
        )

    def _prune_states(self):
        now = self._clock()
        expired = [key for key, value in self._states.items()
                   if value["expires"] <= now]
        for key in expired:
            self._states.pop(key, None)

    def begin_connect(self):
        """Return a Google authorization URL with single-use PKCE state."""
        flow = self._flow()
        url, state = flow.authorization_url(
            access_type="offline", prompt="select_account consent",
            include_granted_scopes="false",
        )
        if not state or not flow.code_verifier:
            raise HostedControlError("Google authorization could not start")
        with self._state_lock:
            self._prune_states()
            self._states[state] = {
                "verifier": flow.code_verifier,
                "expires": self._clock() + OAUTH_TTL_SECONDS,
            }
        return url

    def _take_state(self, state):
        with self._state_lock:
            self._prune_states()
            entry = self._states.pop(str(state or ""), None)
        if entry is None:
            raise HostedControlError(
                "Google sign-in expired or was already used; start again"
            )
        return entry

    def complete_connect(self, query_string):
        """Exchange one callback, verify Gmail identity, and store encrypted."""
        query = urllib.parse.parse_qs(
            str(query_string or ""), keep_blank_values=True
        )
        state = (query.get("state") or [""])[-1]
        entry = self._take_state(state)
        if query.get("error"):
            raise HostedControlError("Google sign-in was cancelled or refused")
        code = (query.get("code") or [""])[-1]
        if not code:
            raise HostedControlError("Google sign-in returned no authorization code")

        flow = self._flow(state=state, code_verifier=entry["verifier"])
        credentials = None
        token_document = None
        service = None
        try:
            flow.fetch_token(
                authorization_response=(
                    self.config.redirect_uri + "?" + str(query_string)
                )
            )
            credentials = flow.credentials
            service = self._service_builder(
                "gmail", "v1", credentials=credentials
            )
            actual = normalize_address(
                gmail_execute(service.users().getProfile(userId="me")).get(
                    "emailAddress", ""
                )
            )
            if not actual:
                raise HostedControlError("Gmail did not identify the account")
            token_document = json.loads(credentials.to_json())
            provider = self._provider_builder(self.config.kms_key)
            return connect_token_document(
                self.config.state_root, actual, token_document, provider
            )
        except HostedControlError:
            raise
        except connection.ConnectionOccupied as exc:
            raise HostedControlError(
                "a different Gmail account is already connected"
            ) from exc
        except Exception as exc:
            raise HostedControlError(
                f"Google sign-in could not be completed ({type(exc).__name__})"
            ) from exc
        finally:
            code = None
            credentials = None
            token_document = None
            service = None

    def disconnect(self, confirmation):
        """Revoke if possible, destroy the local token, and vacate the slot."""
        with connection.lifecycle_lock(self.config.state_root):
            occupant = connection.current(self.config.state_root)
            if occupant is None:
                raise HostedControlError("no Gmail account is connected")
            if not connection.same_account(occupant.account, confirmation):
                raise HostedControlError(
                    "type the connected Gmail address exactly to disconnect"
                )
            try:
                provider = self._provider_builder(self.config.kms_key)
                token_document = connection_tokens.load_token(occupant, provider)
            except Exception:  # noqa: BLE001 - local removal must still happen
                token_document = None
            try:
                return connection_archive.disconnect(
                    occupant, self.config.state_root,
                    revoke=self._revoker if token_document is not None else None,
                    token_document=token_document,
                )
            finally:
                token_document = None
