"""Gmail OAuth flow for a dedicated test Gmail account.

``gmail.modify`` is the least-privileged single scope that supports all
required reads, draft creation, label additions, and rollback-to-Trash.
Google also documents that this scope can send mail. Gmail offers no broad
draft-creation scope that is technically incapable of sending, so the safety
boundary is the application's absence of any send operation, backed by an
automated source regression test. OAuth scope choice is not that boundary.

First run opens your system's default browser for you to sign in to the
test Gmail account and approve access yourself - this script never sees
or handles that password. The resulting token is cached in TOKEN_PATH so
later runs don't prompt again.
"""
import argparse
import logging
import os
import stat

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

DEFAULT_CREDENTIALS_PATH = os.environ.get(
    "GMAIL_CREDENTIALS_PATH", "credentials.json"
)
DEFAULT_TOKEN_PATH = os.environ.get("GMAIL_TOKEN_PATH", "token.json")
# Backward-compatible names for existing imports.
CREDENTIALS_PATH = DEFAULT_CREDENTIALS_PATH
TOKEN_PATH = DEFAULT_TOKEN_PATH

logger = logging.getLogger(__name__)


class TokenUnavailableError(RuntimeError):
    """A usable token was absent where OAuth is not permitted to run."""


def ensure_private_file(path):
    """Restrict a local secret file to its owner without reading it.

    Returns True when the file is absent or has mode 0600 after the check.
    On platforms that do not support POSIX modes, emits a warning and leaves
    permission management to the user/administrator.
    """
    if not os.path.exists(path):
        return True
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode != 0o600:
            os.chmod(path, 0o600)
            logger.warning("Restricted permissions on secret file %s to 0600", path)
        return stat.S_IMODE(os.stat(path).st_mode) == 0o600
    except (OSError, NotImplementedError) as exc:
        logger.warning(
            "Could not verify owner-only permissions for %s (%s). "
            "Restrict this secret file manually before authorizing.",
            path,
            type(exc).__name__,
        )
        return False


def _write_token(creds, token_path):
    """Persist one OAuth token with an owner-only directory and file mode."""
    parent = os.path.dirname(token_path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            logger.warning(
                "Could not enforce 0700 on token directory %s; verify it manually",
                parent,
            )
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as token_file:
        token_file.write(creds.to_json())
    ensure_private_file(token_path)


def get_credentials(credentials_path=None, token_path=None,
                    force_authorize=False, login_hint=None, persist=True,
                    allow_interactive=False):
    """Load one account's token, or explicitly authorize it into a new file.

    Google's sign-in flow opens only when the caller asked for it, via
    ``allow_interactive`` or ``force_authorize``. Both mean "the operator
    typed --authorize"; neither is reachable from a pipeline command.

    A pipeline command pointed at a token path that does not exist used to
    fall through to run_local_server(), mint a brand-new credential for
    whichever account the machine's browser session happened to hold, and
    persist it at that path. The scheduled 6 PM job is exactly this case: it
    pins --token-path so an unattended run cannot use the wrong mailbox, and
    a typo in that path turned the guarantee inside out. An unattended run
    must fail closed instead, which is what refusing here does.
    """
    credentials_path = credentials_path or DEFAULT_CREDENTIALS_PATH
    token_path = token_path or DEFAULT_TOKEN_PATH
    creds = None
    ensure_private_file(credentials_path)
    ensure_private_file(token_path)
    if os.path.exists(token_path) and not force_authorize:
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        elif not (allow_interactive or force_authorize):
            raise TokenUnavailableError(
                f"{token_path} is missing or unusable, and this command will "
                "not open Google's sign-in flow. Authorize it deliberately "
                f"with: python gmail_auth.py --authorize --token-path "
                f"{token_path}"
            )
        else:
            if not os.path.exists(credentials_path):
                raise FileNotFoundError(
                    f"{credentials_path} not found. In Google Cloud Console, "
                    "for the project tied to the test Gmail account: enable "
                    "the Gmail API, create an OAuth client of type 'Desktop "
                    "app', download its JSON, and save it here as "
                    f"{credentials_path}."
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_path, SCOPES
            )
            # Always show account selection and consent so a second profile
            # cannot silently inherit the browser's currently signed-in user.
            auth_options = {
                "port": 0,
                "access_type": "offline",
                "prompt": "select_account consent",
            }
            if login_hint:
                auth_options["login_hint"] = login_hint
            creds = flow.run_local_server(**auth_options)

        if persist:
            _write_token(creds, token_path)

    return creds


def get_gmail_service(credentials_path=None, token_path=None):
    """Return an authorized Gmail API service object.

    Never opens Google's sign-in flow. Pipeline commands call this, and one
    of them is the unattended 6 PM job; authorization is a deliberate,
    separate step via gmail_auth.py --authorize.
    """
    creds = get_credentials(credentials_path, token_path,
                            allow_interactive=False)
    return build("gmail", "v1", credentials=creds)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Authorize a Gmail account and cache its OAuth token."
    )
    parser.add_argument(
        "--authorize", action="store_true",
        help="Open Google's OAuth flow (required; may use the network)",
    )
    parser.add_argument(
        "--credentials-path", default=DEFAULT_CREDENTIALS_PATH,
        help=f"Desktop OAuth client JSON (default: {DEFAULT_CREDENTIALS_PATH})",
    )
    parser.add_argument(
        "--token-path", default=DEFAULT_TOKEN_PATH,
        help=f"Separate token destination (default: {DEFAULT_TOKEN_PATH})",
    )
    parser.add_argument(
        "--reauthorize", action="store_true",
        help="Replace the selected token after showing account consent again",
    )
    parser.add_argument(
        "--expected-account", metavar="EMAIL",
        help="Hint and verify the exact Gmail account after authorization",
    )
    args = parser.parse_args(argv)
    if not args.authorize:
        parser.error("--authorize is required")
    if os.path.exists(args.token_path) and not args.reauthorize:
        parser.error(
            f"{args.token_path} already exists. Use a different --token-path "
            "for another account, or --reauthorize to replace it."
        )
    creds = get_credentials(
        args.credentials_path,
        args.token_path,
        force_authorize=True,
        login_hint=args.expected_account,
        persist=False,
        # The one place interactive OAuth is allowed: the operator typed
        # --authorize.
        allow_interactive=True,
    )
    if args.expected_account:
        service = build("gmail", "v1", credentials=creds)
        actual = service.users().getProfile(userId="me").execute().get(
            "emailAddress", ""
        )
        if actual.casefold() != args.expected_account.casefold():
            raise RuntimeError(
                f"Wrong account authorized: expected {args.expected_account}, "
                f"received {actual}. No token was saved."
            )
        print(f"Verified OAuth account: {actual}")
    _write_token(creds, args.token_path)
    print(f"Authorized. Token cached at {args.token_path}.")


if __name__ == "__main__":
    main()
