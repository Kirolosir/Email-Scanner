"""Separate website identity and Gmail authorization for hosted accounts."""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from connect_account import build_provider
from gmail_auth import SCOPES
from gmail_common import normalize_address
from gmail_retry import gmail_execute
from hosted_control import (
    HostedControlError,
    OAUTH_TTL_SECONDS,
    revoke_google_token,
)
from mailbox_tokens import open_mailbox_token
from tenant_store import PostgresTenantStore, TenantAccessDenied


IDENTITY_SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
)
MAILBOX_SCOPES = tuple(SCOPES) + IDENTITY_SCOPES
MAX_PENDING_STATES = 512
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LoginResult:
    issuer: str
    subject: str
    email: str


def _client_id(credentials_path):
    try:
        document = json.loads(credentials_path.read_text(encoding="utf-8"))
        section = document.get("web") or document.get("installed")
        value = section.get("client_id") if isinstance(section, dict) else None
    except (OSError, json.JSONDecodeError):
        value = None
    if not isinstance(value, str) or not value.strip():
        raise HostedControlError(
            "OAuth client configuration is unavailable",
            code="configuration_failed",
        )
    return value.strip()


class TenantControl:
    def __init__(self, config, store: PostgresTenantStore, *,
                 flow_factory=None, service_builder=build,
                 provider_builder=build_provider, token_verifier=None,
                 revoker=revoke_google_token,
                 clock=time.monotonic):
        self.config = config
        self.store = store
        self.client_id = _client_id(config.credentials_path)
        self._flow_factory = flow_factory or Flow.from_client_secrets_file
        self._service_builder = service_builder
        self._provider_builder = provider_builder
        self._token_verifier = token_verifier or self._verify_google_token
        self._revoker = revoker
        self._clock = clock
        self._states = {}
        self._state_lock = threading.Lock()

    @staticmethod
    def _verify_google_token(raw_token, audience):
        from google.auth.transport.requests import Request  # noqa: PLC0415
        from google.oauth2.id_token import verify_oauth2_token  # noqa: PLC0415

        return verify_oauth2_token(raw_token, Request(), audience=audience)

    def _flow(self, scopes, **kwargs):
        return self._flow_factory(
            str(self.config.credentials_path), scopes,
            redirect_uri=self.config.redirect_uri, **kwargs,
        )

    def _prune_states(self):
        now = self._clock()
        expired = [key for key, value in self._states.items()
                   if value["expires"] <= now]
        for key in expired:
            self._states.pop(key, None)

    def _begin(self, purpose, scopes, user_id=None):
        flow = self._flow(scopes)
        url, state = flow.authorization_url(
            access_type="offline" if purpose == "mailbox" else "online",
            prompt="select_account consent" if purpose == "mailbox" else
                   "select_account",
            include_granted_scopes="false",
        )
        if not state or not flow.code_verifier:
            raise HostedControlError(
                "Google authorization could not start", code="start_failed"
            )
        with self._state_lock:
            self._prune_states()
            if len(self._states) >= MAX_PENDING_STATES:
                raise HostedControlError(
                    "too many Google sign-ins are already pending",
                    code="start_failed",
                )
            self._states[state] = {
                "purpose": purpose,
                "user_id": user_id,
                "verifier": flow.code_verifier,
                "expires": self._clock() + OAUTH_TTL_SECONDS,
            }
        return url

    def begin_login(self):
        return self._begin("login", IDENTITY_SCOPES)

    def begin_mailbox_connect(self, user_id):
        return self._begin("mailbox", MAILBOX_SCOPES, uuid.UUID(str(user_id)))

    def _take_state(self, query_string, purpose, user_id=None):
        query = urllib.parse.parse_qs(
            str(query_string or ""), keep_blank_values=True
        )
        state = (query.get("state") or [""])[-1]
        with self._state_lock:
            self._prune_states()
            entry = self._states.pop(state, None)
        expected_user = uuid.UUID(str(user_id)) if user_id is not None else None
        if (entry is None or entry["purpose"] != purpose
                or entry["user_id"] != expected_user):
            raise HostedControlError(
                "Google sign-in expired or was already used",
                code="state_expired",
            )
        if query.get("error"):
            raise HostedControlError(
                "Google authorization was cancelled or refused",
                code="consent_cancelled",
            )
        code = (query.get("code") or [""])[-1]
        if not code:
            raise HostedControlError(
                "Google returned no authorization code",
                code="callback_invalid",
            )
        return query, state, code, entry

    def _claims(self, credentials):
        raw_token = getattr(credentials, "id_token", None)
        if not isinstance(raw_token, str) or not raw_token:
            raise HostedControlError(
                "Google did not return an identity token",
                code="token_exchange_failed",
            )
        try:
            claims = self._token_verifier(raw_token, self.client_id)
        except Exception as exc:  # noqa: BLE001 - verifier detail stays private
            raise HostedControlError(
                "Google identity could not be verified",
                code="token_exchange_failed",
            ) from exc
        issuer = str(claims.get("iss") or "")
        subject = str(claims.get("sub") or "")
        email = normalize_address(claims.get("email") or "")
        if (issuer not in {"accounts.google.com", "https://accounts.google.com"}
                or not subject or not email
                or claims.get("email_verified") is not True):
            raise HostedControlError(
                "Google identity was incomplete",
                code="token_exchange_failed",
            )
        return LoginResult(issuer, subject, email)

    def complete_login(self, query_string):
        _query, state, code, entry = self._take_state(
            query_string, "login"
        )
        flow = self._flow(
            IDENTITY_SCOPES, state=state, code_verifier=entry["verifier"]
        )
        try:
            flow.fetch_token(code=code, include_client_id=True)
            return self._claims(flow.credentials)
        except HostedControlError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider detail stays private
            logger.warning("Website sign-in failed (%s)", type(exc).__name__)
            raise HostedControlError(
                "Google sign-in could not be completed",
                code="token_exchange_failed",
            ) from exc

    def complete_mailbox_connect(self, query_string, user_id):
        _query, state, code, entry = self._take_state(
            query_string, "mailbox", user_id
        )
        flow = self._flow(
            MAILBOX_SCOPES, state=state, code_verifier=entry["verifier"]
        )
        credentials = None
        token_document = None
        try:
            flow.fetch_token(code=code, include_client_id=True)
            credentials = flow.credentials
            identity = self._claims(credentials)
            service = self._service_builder(
                "gmail", "v1", credentials=credentials
            )
            actual = normalize_address(
                gmail_execute(service.users().getProfile(userId="me")).get(
                    "emailAddress", ""
                )
            )
            if not actual or actual != identity.email:
                raise HostedControlError(
                    "Google identity did not match the Gmail account",
                    code="gmail_profile_failed",
                )
            token_document = json.loads(credentials.to_json())
            provider = self._provider_builder(self.config.kms_key)
            return self.store.connect_mailbox(
                uuid.UUID(str(user_id)), identity.subject, actual,
                token_document, provider,
            )
        except (HostedControlError, TenantAccessDenied):
            raise
        except Exception as exc:  # noqa: BLE001 - provider detail stays private
            logger.warning("Gmail connection failed (%s)", type(exc).__name__)
            raise HostedControlError(
                "Gmail connection could not be completed",
                code="credential_storage_failed",
            ) from exc
        finally:
            credentials = None
            token_document = None

    def disconnect_mailbox(self, user_id, mailbox_id, confirmation):
        mailbox = self.store.mailbox_for_user(user_id, mailbox_id)
        if normalize_address(confirmation) != normalize_address(mailbox.address):
            raise HostedControlError(
                "type the connected Gmail address exactly to disconnect"
            )
        token_document = None
        try:
            provider = self._provider_builder(self.config.kms_key)
            record = self.store.load_credentials(user_id, mailbox_id)
            token_document = open_mailbox_token(mailbox_id, record, provider)
            try:
                self._revoker(token_document)
            except Exception:  # noqa: BLE001 - local removal must still happen
                logger.warning("Google revocation failed during disconnect")
        finally:
            token_document = None
            self.store.disconnect_mailbox(user_id, mailbox_id)
        return True
