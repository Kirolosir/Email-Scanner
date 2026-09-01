"""Pure, offline safety policy for inbound Gmail messages.

This module deliberately has no Gmail, OAuth, Gemini, or filesystem access.
It centralizes the conservative checks used before an email may be classified,
labeled as a recruit, or addressed by a draft.
"""
from __future__ import annotations

import hashlib
import re
from email.utils import getaddresses, parseaddr


DEFAULT_MAX_BODY_CHARS = 8_000
MIN_MAX_BODY_CHARS = 500
MAX_MAX_BODY_CHARS = 50_000

AUTOMATED_LOCAL_PART = re.compile(
    # 'bounces?' covers both bounce@ and bounces@, and - because the token
    # only needs a delimiter after it - VERP return paths such as
    # bounce-123-abc@ and bounces+token@. A human address like bouncer@ is
    # not matched, since 'r' is neither a delimiter nor end-of-string.
    r"(?:^|[._+-])(?:no-?reply|do-?not-?reply|mailer-daemon|postmaster"
    r"|bounces?)"
    r"(?:$|[._+-])",
    re.IGNORECASE,
)
EMAIL_ADDRESS = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}$",
    re.IGNORECASE,
)

QUOTE_START = re.compile(r"^\s*On\s+.+\bwrote:\s*$", re.IGNORECASE)
FORWARD_START = re.compile(
    r"^\s*(?:-{2,}\s*(?:Original Message|Forwarded message)\s*-{2,}"
    r"|Begin forwarded message:)\s*$",
    re.IGNORECASE,
)
SIGNATURE_START = re.compile(r"^\s*--\s*$")
MOBILE_SIGNATURE = re.compile(
    r"^\s*(?:Sent from my (?:iPhone|iPad|Android)|Get Outlook for (?:iOS|Android))",
    re.IGNORECASE,
)
SIGNOFF = re.compile(
    r"^\s*(?:best|best regards|regards|thanks|thank you|sincerely|cheers),?\s*$",
    re.IGNORECASE,
)


def validate_max_body_chars(value):
    """Return a bounded integer suitable for model-input truncation."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("maximum body characters must be an integer") from exc
    if not MIN_MAX_BODY_CHARS <= parsed <= MAX_MAX_BODY_CHARS:
        raise ValueError(
            "maximum body characters must be between "
            f"{MIN_MAX_BODY_CHARS} and {MAX_MAX_BODY_CHARS}"
        )
    return parsed


def _valid_address(address):
    return bool(address and EMAIL_ADDRESS.fullmatch(address))


def single_address(header_value):
    """Resolve exactly one conservative RFC-style mailbox.

    Returns ``(normalized_address, error_code)``. Display names are accepted;
    multiple or syntactically dubious mailboxes are not guessed through.
    """
    value = (header_value or "").strip()
    if not value:
        return "", "missing_address"
    parsed = [(name, address.strip().casefold())
              for name, address in getaddresses([value]) if name or address]
    if len(parsed) != 1:
        return "", "multiple_or_malformed_addresses"
    address = parsed[0][1]
    # parseaddr catches trailing junk that getaddresses may otherwise split
    # permissively. The round trip must resolve to the same mailbox.
    if parseaddr(value)[1].strip().casefold() != address or not _valid_address(address):
        return "", "malformed_address"
    return address, ""


def is_automated_address(address):
    local = (address or "").partition("@")[0]
    return bool(AUTOMATED_LOCAL_PART.search(local))


def assess_delivery_headers(headers, own_address=""):
    """Classify delivery metadata before any body or model processing.

    ``headers`` is a case-insensitive mapping represented with lower-case
    names. The returned mapping contains only fixed reason codes, never header
    values, which makes it safe to summarize in unattended logs.
    """
    normalized = {str(key).casefold(): str(value or "")
                  for key, value in (headers or {}).items()}
    sender, sender_error = single_address(normalized.get("from", ""))
    reply_raw = normalized.get("reply-to", "").strip()
    reply_address, reply_error = (
        single_address(reply_raw) if reply_raw else ("", "")
    )

    automated_codes = []
    auto_submitted = normalized.get("auto-submitted", "").strip().casefold()
    if auto_submitted and auto_submitted != "no":
        automated_codes.append("auto_submitted")
    if normalized.get("precedence", "").strip().casefold() in {
        "bulk", "list", "junk"
    }:
        automated_codes.append("bulk_precedence")
    if normalized.get("list-unsubscribe", "").strip():
        automated_codes.append("mailing_list")
    auto_suppress = normalized.get("x-auto-response-suppress", "").strip().casefold()
    if auto_suppress and auto_suppress not in {"no", "none"}:
        automated_codes.append("auto_response_suppressed")
    if is_automated_address(sender):
        automated_codes.append("automated_sender")
    if reply_address and is_automated_address(reply_address):
        automated_codes.append("automated_reply_target")

    if automated_codes:
        return {
            "status": "automated",
            "sender": sender,
            "reply_address": "",
            "reason_codes": sorted(set(automated_codes)),
        }

    ambiguity = []
    if sender_error:
        ambiguity.append(f"from_{sender_error}")
    if reply_raw and reply_error:
        ambiguity.append(f"reply_to_{reply_error}")
    target = reply_address or sender
    if target and is_automated_address(target):
        ambiguity.append("unsafe_reply_target")
    owner = parseaddr(own_address or "")[1].strip().casefold()
    if owner and target == owner:
        ambiguity.append("reply_target_is_account_owner")

    if ambiguity or not target:
        return {
            "status": "ambiguous",
            "sender": sender,
            "reply_address": "",
            "reason_codes": sorted(set(ambiguity or ["missing_reply_target"])),
        }
    return {
        "status": "normal",
        "sender": sender,
        "reply_address": target,
        "reason_codes": [],
    }


def clean_current_message(body, max_chars=DEFAULT_MAX_BODY_CHARS):
    """Return only the likely current top-posted plain-text message.

    Quoted replies, forwarded blocks, common signatures, and quote-prefixed
    lines are excluded conservatively. The result contains fixed metadata
    flags and never retains removed text.
    """
    maximum = validate_max_body_chars(max_chars)
    text = (body or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    kept = []
    removed_quoted = False
    removed_signature = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if QUOTE_START.match(line) or FORWARD_START.match(line):
            removed_quoted = True
            break
        if re.match(r"^\s*From:\s+", line, re.IGNORECASE):
            header_window = "\n".join(lines[index:index + 6])
            header_markers = sum(bool(re.search(
                rf"^\s*{name}:\s+", header_window,
                re.IGNORECASE | re.MULTILINE,
            )) for name in ("Sent", "Date", "To", "Subject"))
            if header_markers >= 2:
                removed_quoted = True
                break
        # Some clients wrap "On ... wrote:" across two or three lines.
        if re.match(r"^\s*On\s+", line, re.IGNORECASE):
            window = " ".join(lines[index:index + 3])
            if re.search(r"\bwrote:\s*$", window.strip(), re.IGNORECASE):
                removed_quoted = True
                break
        if stripped.startswith(">"):
            removed_quoted = True
            continue
        if SIGNATURE_START.match(line) or MOBILE_SIGNATURE.match(line):
            removed_signature = True
            break
        if kept and SIGNOFF.match(line):
            removed_signature = True
            break
        kept.append(line.rstrip())

    cleaned = "\n".join(kept).strip()
    # Collapse excessive blank space without flattening useful paragraphs.
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    truncated = len(cleaned) > maximum
    if truncated:
        cleaned = cleaned[:maximum].rstrip()
    meaningful = bool(re.search(r"[A-Za-z0-9]", cleaned))
    return {
        "text": cleaned if meaningful else "",
        "truncated": truncated,
        "removed_quoted": removed_quoted,
        "removed_signature": removed_signature,
        "meaningful": meaningful,
    }


YEAR_PATTERNS = (
    ("class_of_year", re.compile(
        r"\bclass\s+of\s+(?P<year>20\d{2})\b", re.IGNORECASE)),
    ("year_grad", re.compile(
        r"\b(?P<year>20\d{2})\s+(?:grad(?:uate)?|recruit|prospect)\b",
        re.IGNORECASE)),
    ("graduating_year", re.compile(
        r"\bgraduat(?:e|ing|ion)(?:\s+year)?\s*(?:in|of|:|-)?\s*"
        r"(?P<year>20\d{2})\b", re.IGNORECASE)),
    ("grad_year_field", re.compile(
        r"\b(?:grad(?:uation)?\s*year|class)\s*[:=-]\s*"
        r"(?P<year>20\d{2})\b", re.IGNORECASE)),
    ("self_identified_year", re.compile(
        r"\bI(?:'m| am)\s+(?:a\s+)?(?P<year>20\d{2})"
        r"\s+(?:grad(?:uate)?|recruit|prospect)\b", re.IGNORECASE)),
    ("short_recruit_year", re.compile(
        r"\b(?:class|grad(?:uation)?\s*year|recruit|prospect)\s*"
        r"(?:of\s+)?['’](?P<short>\d{2})\b", re.IGNORECASE)),
    ("short_year_recruit", re.compile(
        r"['’](?P<short>\d{2})\s+"
        r"(?:grad(?:uate)?|recruit|prospect)\b", re.IGNORECASE)),
)


def extract_grad_year_evidence(body, subject="", supported_years=None):
    """Extract deterministic, context-bound graduation-year evidence."""
    supported = set(supported_years or ())
    text = "\n".join(part for part in (subject or "", body or "") if part)
    findings = []
    for code, pattern in YEAR_PATTERNS:
        for match in pattern.finditer(text):
            year = match.groupdict().get("year")
            if not year:
                year = f"20{match.group('short')}"
            if supported and year not in supported:
                continue
            findings.append((year, code))
    years = sorted({year for year, _code in findings})
    return {
        "grad_year": years[0] if len(years) == 1 else "unknown",
        "evidence_codes": sorted({code for _year, code in findings}),
        "ambiguous": len(years) > 1,
    }


def opaque_id(value, length=12):
    """Return a stable, non-reversible identifier suitable for private logs."""
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:length]
