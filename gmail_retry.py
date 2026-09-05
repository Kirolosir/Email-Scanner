"""Transient-failure retry for Gmail API calls.

A leaf module on purpose: every Gmail-touching module imports this, so it
must import nothing from the project or it reintroduces an import cycle.

Gemini calls already retried with backoff; Gmail calls had nothing. A live
run took 143 rate-limit rejections and then died with BrokenPipeError - the
keep-alive socket had been closed server-side during the storm, and the next
call reused it. Both halves matter: retrying a dead connection without
rebuilding it just fails again on the same socket.
"""
from __future__ import annotations

import http.client
import json
import random
import socket
import ssl
import time

MAX_GMAIL_ATTEMPTS = 5
MAX_GMAIL_BACKOFF_SECONDS = 32

# 5xx and 429 are always worth retrying. 403 is not: it is also permission
# denied, which retrying cannot fix. Only the rate-limit reasons qualify.
RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRYABLE_403_REASONS = frozenset({
    "ratelimitexceeded",
    "userratelimitexceeded",
    "backenderror",
    "quotaexceeded",
})

# Connection-level faults. Listed explicitly rather than catching OSError,
# which would also swallow genuine local errors such as a missing file.
TRANSPORT_FAULTS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
    TimeoutError,
    socket.gaierror,
    ssl.SSLError,
    http.client.BadStatusLine,
    http.client.IncompleteRead,
    http.client.CannotSendRequest,
    http.client.ResponseNotReady,
)


def http_error_status(error):
    """HTTP status carried by a googleapiclient HttpError, or None."""
    response = getattr(error, "resp", None)
    status = getattr(response, "status", None)
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def http_error_reason(error):
    """Google's machine-readable reason string, casefolded, or ''."""
    content = getattr(error, "content", None)
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    if not content:
        return ""
    try:
        payload = json.loads(content)
    except (ValueError, TypeError):
        return ""
    errors = (payload.get("error") or {}).get("errors") or []
    for item in errors:
        reason = (item or {}).get("reason")
        if reason:
            return str(reason).casefold()
    return ""


def describe_http_error(error):
    """Render an HttpError for a failure record: '403 rateLimitExceeded'.

    Recording only type(exc).__name__ made every Gmail fault read
    'HttpError', so a transient rate limit was indistinguishable from a
    permanent permission error in the run output.
    """
    status = http_error_status(error)
    reason = http_error_reason(error)
    if status and reason:
        return f"{status} {reason}"
    if status:
        return str(status)
    return type(error).__name__


def is_retryable_http_error(error):
    """Whether this HTTP failure is worth another attempt."""
    status = http_error_status(error)
    if status is None:
        return False
    if status in RETRYABLE_HTTP_STATUSES:
        return True
    if status == 403:
        return http_error_reason(error) in RETRYABLE_403_REASONS
    return False


def reset_http_connections(request):
    """Drop cached connections so a retry dials a fresh socket.

    httplib2 keeps a connection pool on the Http object and will happily
    reuse a socket the server has already closed. google-auth wraps that
    Http in an AuthorizedHttp, so the wrapper is unwrapped here first.
    """
    candidate = getattr(request, "http", None)
    seen = set()
    while candidate is not None and id(candidate) not in seen:
        seen.add(id(candidate))
        connections = getattr(candidate, "connections", None)
        if isinstance(connections, dict):
            for connection in list(connections.values()):
                try:
                    connection.close()
                except Exception:  # noqa: BLE001 - closing is best effort
                    pass
            connections.clear()
        candidate = getattr(candidate, "http", None)


def _gmail_backoff(attempt):
    base = min(MAX_GMAIL_BACKOFF_SECONDS, 2 ** (attempt - 1))
    return min(MAX_GMAIL_BACKOFF_SECONDS, base + random.uniform(0, base * 0.25))


def gmail_execute(request, *, attempts=MAX_GMAIL_ATTEMPTS, sleeper=time.sleep):
    """Execute one Gmail API request, retrying transient failures.

    Retries rate limits and 5xx, and connection-level faults after
    rebuilding the connection. A non-retryable error (404, a real 403) is
    raised immediately rather than slept on.
    """
    from googleapiclient.errors import HttpError

    last = None
    for attempt in range(1, max(1, int(attempts)) + 1):
        try:
            return request.execute()
        except TRANSPORT_FAULTS as exc:
            last = exc
            # The socket is dead. Reusing it fails identically.
            reset_http_connections(request)
        except HttpError as exc:
            if not is_retryable_http_error(exc):
                raise
            last = exc
        if attempt >= max(1, int(attempts)):
            break
        sleeper(_gmail_backoff(attempt))
    raise last





def describe_failure(error):
    """Render any Gmail failure for a run's failure record.

    HTTP faults become '403 rateLimitExceeded'; transport faults keep their
    exception name. Recording type(exc).__name__ alone made every fault read
    'HttpError', hiding whether a run should be retried or investigated.
    """
    from googleapiclient.errors import HttpError

    if isinstance(error, HttpError):
        return describe_http_error(error)
    return type(error).__name__
