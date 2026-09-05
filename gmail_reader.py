"""Read-only helpers for pulling messages out of Gmail: resolving a label
name to its id, listing message ids under that label, and extracting a
clean plain-text body from a message (handling base64url encoding and
nested multipart MIME structures). No write or send calls live here."""
import base64
import re
from gmail_retry import gmail_execute


def get_label_id(service, label_name):
    """Look up a label's id by its display name (case-insensitive).

    Raises ValueError if no label with that name exists.
    """
    labels = gmail_execute(service.users().labels().list(userId="me")).get("labels", [])
    for label in labels:
        if label["name"].lower() == label_name.lower():
            return label["id"]
    available = ", ".join(l["name"] for l in labels)
    raise ValueError(f"No label named {label_name!r}. Available labels: {available}")


def list_message_ids(service, label_name, max_results=10):
    """Return message ids for messages under the given label name."""
    label_id = get_label_id(service, label_name)
    response = gmail_execute(service.users().messages().list(
        userId="me", labelIds=[label_id], maxResults=max_results
    ))
    return [m["id"] for m in response.get("messages", [])]


def get_message(service, message_id):
    """Fetch one full message resource by id."""
    return gmail_execute(service.users().messages().get(
        userId="me", id=message_id, format="full"
    ))


def get_header(message, name):
    """Look up one header value (e.g. 'Subject', 'From') from a message."""
    headers = message.get("payload", {}).get("headers", [])
    for h in headers:
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""


def get_header_values(message, name):
    """Return every occurrence of a header, preserving Gmail order."""
    headers = message.get("payload", {}).get("headers", [])
    return [
        header.get("value", "") for header in headers
        if header.get("name", "").casefold() == name.casefold()
    ]


def _decode_part_body(data):
    """Gmail API part bodies are base64url-encoded; decode to text,
    tolerating the missing padding Gmail's encoding omits."""
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _walk_parts(payload):
    """Yield every leaf MIME part in a (possibly nested) message payload.
    Simple messages have no "parts" list at all - the payload itself is
    the one leaf part."""
    if _is_attachment(payload) or payload.get("mimeType", "").casefold() == "message/rfc822":
        return
    parts = payload.get("parts")
    if not parts:
        yield payload
        return
    for part in parts:
        yield from _walk_parts(part)


def _is_attachment(part):
    """Return True for MIME parts that must never become classifier input."""
    if (part.get("filename") or "").strip():
        return True
    for header in part.get("headers", []):
        if header.get("name", "").casefold() == "content-disposition":
            if header.get("value", "").strip().casefold().startswith("attachment"):
                return True
    return False


def get_plain_text_body(message):
    """Extract a clean plain-text body from a Gmail API message resource
    (format="full").

    Prefers text/plain parts, concatenated in order. If a message is
    HTML-only (no text/plain part anywhere), falls back to stripping tags
    out of the text/html part so the tool always gets usable text instead
    of raw markup.
    """
    payload = message.get("payload", {})

    plain_chunks = []
    html_chunks = []
    for part in _walk_parts(payload):
        if _is_attachment(part):
            continue
        body_data = part.get("body", {}).get("data")
        if not body_data:
            continue
        text = _decode_part_body(body_data)
        mime_type = part.get("mimeType", "")
        if mime_type == "text/plain":
            plain_chunks.append(text)
        elif mime_type == "text/html":
            html_chunks.append(text)

    if plain_chunks:
        return "\n".join(plain_chunks).strip()

    if html_chunks:
        stripped = re.sub(r"<[^>]+>", " ", "\n".join(html_chunks))
        return re.sub(r"\s+", " ", stripped).strip()

    return ""
