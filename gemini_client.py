"""Gemini wrapper for the email triage tool: text extraction, response
parsing, and a rate-limited, retrying classify() call.

Importing this module has no side effects (no API calls, no prints) so
it's safe to import from the Gmail triage script or from tests.
"""
import logging
import os
import random
import re
import time

from dotenv import load_dotenv
from google import genai

import account_profile as _profile_module
from account_profile import load_profile as _load_profile

_PROFILE = _load_profile()

# Override via GEMINI_MODEL in .env to swap models without editing code
# (e.g. if the free-tier daily quota on one model gets exhausted).
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")


def _validated_float_env(name, default, minimum=0.0, maximum=60.0):
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}, got {value}"
        )
    return value


# Six seconds is the safe default for a roughly ten-requests/minute free tier.
THROTTLE_SECONDS = _validated_float_env("GEMINI_THROTTLE_SECONDS", 6.0)
MAX_BACKOFF_SECONDS = _validated_float_env(
    "GEMINI_MAX_BACKOFF_SECONDS", 30.0, minimum=1.0, maximum=120.0
)

# Sourced from the account profile so no category name is a literal here.
VALID_CATEGORIES = set(_PROFILE.valid_categories)
VALID_SENDER_TYPES = set(_profile_module.VALID_SENDER_TYPES)
VALID_CONFIDENCE = set(_profile_module.VALID_CONFIDENCE)


def _validated_years_env():
    raw_years = [year.strip() for year in os.environ.get(
        "GEMINI_GRAD_YEARS", ",".join(sorted(_PROFILE.supported_years))
    ).split(",")]
    if not raw_years or any(not re.fullmatch(r"20\d{2}", year)
                            for year in raw_years):
        raise ValueError(
            "GEMINI_GRAD_YEARS must be a comma-separated list of four-digit years"
        )
    return set(raw_years)


SUPPORTED_GRAD_YEARS = _validated_years_env()

logger = logging.getLogger(__name__)

PROMPT = """You are sorting emails for a college men's soccer coach.

Classify this email. Respond in exactly this format, nothing else:

CATEGORY: <recruit_intro | recruit_update | video_update | parent | other_coach | camp_inquiry | administrative | other | unknown>
GRAD_YEAR: <the four-digit year, or unknown>
SENDER_TYPE: <recruit | parent | coach | administrative | other | unknown>
CONFIDENCE: <high | medium | low>
EVIDENCE: <one short phrase identifying the current-message evidence>
REASON: <one short sentence>

From: {sender}
Subject: {subject}
Body: {body}
"""

_last_call_time = 0.0
_call_count = 0
_client = None
_environment_loaded = False


def get_client():
    """Create the Gemini client only when a live classification is requested."""
    global _client, _environment_loaded
    if _client is None:
        # Loading .env is deliberately delayed until the caller explicitly
        # starts a live Gemini classification. Imports, --help, demos, and
        # offline tests never read the secret file.
        if not _environment_loaded:
            load_dotenv()
            _environment_loaded = True
        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured; live Gemini is unavailable"
            )
        _client = genai.Client(api_key=api_key)
    return _client


def _throttle():
    """Block until at least THROTTLE_SECONDS have passed since the last
    Gemini call, so batch loops stay under the account's rate limit."""
    global _last_call_time
    wait = THROTTLE_SECONDS - (time.monotonic() - _last_call_time)
    if wait > 0:
        time.sleep(wait)
    _last_call_time = time.monotonic()


def get_call_count():
    """Total Gemini API calls made (including retries) since the last
    reset_call_count(), so a batch run can report what it actually cost."""
    return _call_count


def reset_call_count():
    """Zero the call counter, e.g. before timing a batch run."""
    global _call_count
    _call_count = 0


def get_text(response):
    """Pull response text safely even when any response layer is missing."""
    candidates = getattr(response, "candidates", None) or []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        parts = getattr(content, "parts", None) or []
        for part in parts:
            text = getattr(part, "text", None)
            if text:
                return text
    return ""


def parse_result(text):
    """Turn the model's formatted response into a dict.

    Malformed or unsupported fields become ``unknown``. Raw model output is
    deliberately not logged because it could echo a recruit's email body.
    """
    result = {}
    duplicate = False
    for line in (text or "").strip().split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if key in result:
                duplicate = True
            result[key] = value.strip()

    required = {
        "category", "grad_year", "sender_type", "confidence", "evidence", "reason"
    }
    malformed = duplicate or set(result) != required or any(
        not result.get(key, "").strip() for key in required
    )
    if malformed:
        logger.warning(
            "Classifier returned malformed structure; response length=%d",
            len(text or ""),
        )
        return {
            "category": "unknown",
            "grad_year": "unknown",
            "sender_type": "unknown",
            "confidence": "unknown",
            "evidence": "",
            "reason": "classification structure was invalid",
            "valid": False,
        }

    category = result.get("category", "").strip().lower()
    if category not in VALID_CATEGORIES:
        logger.warning(
            "Classifier returned missing/unsupported category; response length=%d",
            len(text or ""),
        )
        category = "unknown"
    result["category"] = category

    grad_year = result.get("grad_year", "").strip().lower()
    if grad_year in {"", "unknown", "none", "n/a"}:
        grad_year = "unknown"
    elif grad_year not in SUPPORTED_GRAD_YEARS:
        logger.warning("Classifier returned unsupported graduation year")
        grad_year = "unknown"
    result["grad_year"] = grad_year

    sender_type = result.get("sender_type", "").strip().lower()
    if sender_type not in VALID_SENDER_TYPES:
        logger.warning("Classifier returned unsupported sender type")
        sender_type = "unknown"
    result["sender_type"] = sender_type

    confidence = result.get("confidence", "").strip().lower()
    if confidence not in VALID_CONFIDENCE:
        logger.warning("Classifier returned unsupported confidence")
        confidence = "unknown"
    result["confidence"] = confidence

    evidence = result.get("evidence", "").strip()
    if len(evidence) > 160:
        logger.warning("Classifier evidence exceeded the allowed length")
        evidence = evidence[:160]
    result["evidence"] = evidence

    reason = result.get("reason", "").strip()
    if len(reason) > 240:
        logger.warning("Classifier reason exceeded the allowed length")
        reason = reason[:240]
    result["reason"] = reason
    result["valid"] = (
        category != "unknown"
        and sender_type != "unknown"
        and confidence in VALID_CONFIDENCE
        and grad_year in SUPPORTED_GRAD_YEARS | {"unknown"}
    )

    return result


def _status_code(error):
    for candidate in (
        getattr(error, "code", None),
        getattr(error, "status_code", None),
        getattr(getattr(error, "response", None), "status_code", None),
    ):
        try:
            if candidate is not None:
                return int(candidate)
        except (TypeError, ValueError):
            continue
    return None


def is_transient_error(error):
    """Identify only rate-limit, timeout, connection, and server failures."""
    status = _status_code(error)
    if status in {408, 429, 500, 502, 503, 504}:
        return True
    return isinstance(error, (TimeoutError, ConnectionError, OSError))


def _backoff(attempt):
    base = min(MAX_BACKOFF_SECONDS, 2 ** (attempt - 1))
    time.sleep(min(MAX_BACKOFF_SECONDS, base + random.uniform(0, base * 0.25)))


def generate_text(prompt, max_retries=3, model=None):
    """One free-form Gemini call returning raw text.

    Shares classify()'s throttle, call counting, and transient-error retry
    policy, so discovery cannot bypass the account's pacing. Returns the
    response text; raises RuntimeError when no text arrives.
    """
    if not isinstance(max_retries, int) or max_retries <= 0:
        raise ValueError("max_retries must be a positive integer")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    model = model or MODEL

    global _call_count
    last_error = None
    for attempt in range(1, max_retries + 1):
        _throttle()
        _call_count += 1
        try:
            response = get_client().models.generate_content(
                model=model, contents=prompt,
            )
        except Exception as exc:
            status = _status_code(exc)
            if not is_transient_error(exc):
                raise RuntimeError(
                    "Permanent Gemini error; not retried "
                    f"({type(exc).__name__}, status={status or 'unknown'})"
                ) from exc
            last_error = exc
            logger.warning(
                "Transient Gemini error on attempt %d/%d (%s, status=%s)",
                attempt, max_retries, type(exc).__name__, status or "unknown",
            )
            if attempt < max_retries:
                _backoff(attempt)
            continue

        text = get_text(response)
        if text:
            return text
        logger.warning("Empty Gemini response on attempt %d/%d",
                       attempt, max_retries)
        if attempt < max_retries:
            _backoff(attempt)

    raise RuntimeError(
        f"No Gemini text after {max_retries} attempts"
    ) from last_error


def classify(email, max_retries=3, model=None):
    """Classify one email dict ({"from", "subject", "body"}) via Gemini.

    Retries on empty responses and on transient API errors (e.g. a 429
    rate limit), throttling before every call attempt. Raises RuntimeError
    only after max_retries is exhausted, so callers can catch that per
    email and keep going rather than losing the whole batch.

    `model` defaults to the module-level MODEL but can be overridden per
    call, e.g. to compare models within the same run.
    """
    if not isinstance(max_retries, int) or max_retries <= 0:
        raise ValueError("max_retries must be a positive integer")
    model = model or MODEL
    prompt = PROMPT.format(
        sender=email["from"],
        subject=email["subject"],
        body=email["body"],
    )

    global _call_count
    last_error = None
    for attempt in range(1, max_retries + 1):
        _throttle()
        _call_count += 1
        try:
            response = get_client().models.generate_content(
                model=model,
                contents=prompt,
            )
        except Exception as exc:
            status = _status_code(exc)
            if not is_transient_error(exc):
                raise RuntimeError(
                    "Permanent Gemini error; not retried "
                    f"({type(exc).__name__}, status={status or 'unknown'})"
                ) from exc
            last_error = exc
            logger.warning(
                "Transient Gemini error on attempt %d/%d (%s, status=%s)",
                attempt, max_retries, type(exc).__name__, status or "unknown",
            )
            if attempt < max_retries:
                _backoff(attempt)
            continue

        text = get_text(response)
        if text:
            return parse_result(text)

        logger.warning("Empty Gemini response on attempt %d/%d", attempt, max_retries)
        if attempt < max_retries:
            _backoff(attempt)

    if last_error is not None:
        raise RuntimeError(
            f"Gemini transient error after {max_retries} tries"
        ) from last_error
    raise RuntimeError(f"No Gemini response after {max_retries} tries")
