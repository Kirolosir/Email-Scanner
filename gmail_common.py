"""Gmail utilities shared by the campaign mail merge and the triage
pipeline: quota throttling, paginated message listing, address
normalization, and reply-draft MIME construction.

Nothing here sends. The draft builder produces a draft resource; the
caller decides what to do with it.
"""
import base64
import time
import threading
from email.message import EmailMessage
from email.utils import parseaddr

from gmail_reader import get_label_id
from gmail_retry import gmail_execute

# Gmail API quota costs, in units, per
# https://developers.google.com/gmail/api/reference/quota
UNITS_MESSAGES_LIST = 5
UNITS_MESSAGES_GET = 20
UNITS_DRAFTS_CREATE = 10
UNITS_DRAFTS_LIST = 5
UNITS_DRAFTS_GET = 20
UNITS_MESSAGES_TRASH = 20

# Gmail currently allows 6,000 units/user/minute. Pace at 5,400/minute
# (90/second average) so retries or a concurrent session have headroom.
QUOTA_UNITS_PER_SECOND = 90

# Gmail returns at most 500 message ids per list page.
LIST_PAGE_SIZE = 500

class QuotaThrottle:
    """Smooth throttle over Gmail's per-minute user quota.

    Callers declare request cost before making it. The leaky-bucket schedule
    supports large batch costs without ever treating a request larger than a
    one-second allowance as a special case.
    """

    def __init__(self, units_per_second=QUOTA_UNITS_PER_SECOND):
        self.units_per_second = units_per_second
        if units_per_second <= 0:
            raise ValueError("units_per_second must be positive")
        self._next_available = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, units):
        if units < 0:
            raise ValueError("quota units cannot be negative")
        from runtime_metrics import add
        add("gmail_quota_units", units)
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_available)
            wait = scheduled - now
            if wait > 0:
                time.sleep(wait)
            self._next_available = scheduled + (units / self.units_per_second)


def normalize_address(from_header):
    """Reduce a From header to a bare lowercase email address.

    'Coach Bob <Bob@Example.COM>' -> 'bob@example.com'
    """
    _, address = parseaddr(from_header or "")
    return address.strip().lower()


def list_all_message_ids(service, label_name, throttle, max_scan=None,
                         progress=True):
    """Page through every message under a label, returning message ids.

    Gmail caps each page at 500, so a ~9,000 message label needs ~18
    round trips.
    """
    label_id = get_label_id(service, label_name)

    message_ids = []
    page_token = None
    while True:
        throttle.consume(UNITS_MESSAGES_LIST)
        response = gmail_execute(service.users().messages().list(
            userId="me",
            labelIds=[label_id],
            maxResults=LIST_PAGE_SIZE,
            pageToken=page_token,
        ))

        message_ids.extend(m["id"] for m in response.get("messages", []))
        if progress:
            print(f"  listed {len(message_ids)} messages...", end="\r", flush=True)

        if max_scan is not None and len(message_ids) >= max_scan:
            message_ids = message_ids[:max_scan]
            break

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    if progress:
        print(f"  listed {len(message_ids)} messages    ")
    return message_ids


def list_message_ids_by_query(service, query, throttle, max_scan=None,
                              progress=True):
    """Page through message ids matching one reviewed Gmail search query.

    The query is constructed by daily_triage.py, never from email/model text.
    ``max_scan`` limits ids returned before any message bodies are fetched.
    """
    if not isinstance(query, str) or not query.strip():
        raise ValueError("Gmail query must be a non-empty string")
    if max_scan is not None and max_scan <= 0:
        raise ValueError("max_scan must be greater than zero")

    message_ids = []
    page_token = None
    while True:
        throttle.consume(UNITS_MESSAGES_LIST)
        response = gmail_execute(service.users().messages().list(
            userId="me",
            q=query,
            maxResults=LIST_PAGE_SIZE,
            pageToken=page_token,
        ))
        message_ids.extend(item["id"] for item in response.get("messages", []))

        if progress:
            print(f"  listed {len(message_ids)} messages...", end="\r", flush=True)
        if max_scan is not None and len(message_ids) >= max_scan:
            message_ids = message_ids[:max_scan]
            break
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    if progress:
        print(f"  listed {len(message_ids)} messages    ")
    return message_ids


def build_draft_body(record, body_text):
    """Build the Gmail draft resource for a reply on an existing thread.

    Sets In-Reply-To/References to the original Message-ID so Gmail files
    the draft inside the existing conversation rather than starting a new
    one. 'From' is intentionally unset - Gmail fills in the authorized
    account.

    `record` needs: sender/reply_address, subject, rfc_message_id, thread_id.
    """
    message = EmailMessage()
    message["To"] = record.get("reply_address") or record["sender"]

    subject = record["subject"] or ""
    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}" if subject else "Re:"
    message["Subject"] = subject

    if record["rfc_message_id"]:
        message["In-Reply-To"] = record["rfc_message_id"]
        message["References"] = record["rfc_message_id"]

    message.set_content(body_text)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"message": {"raw": raw, "threadId": record["thread_id"]}}
