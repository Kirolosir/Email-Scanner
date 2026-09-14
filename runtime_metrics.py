"""PII-free counters for one mailbox-processing run."""
from __future__ import annotations

import contextvars
import os


_METRICS = contextvars.ContextVar("email_scanner_metrics", default=None)


def reset():
    metrics = {
        "gmail_requests": 0,
        "gmail_retries": 0,
        "gmail_quota_units": 0,
        "gemini_calls": 0,
        "gemini_input_tokens": 0,
        "gemini_output_tokens": 0,
        "estimated_cost_microusd": 0,
    }
    _METRICS.set(metrics)
    return metrics


def add(key, amount=1):
    metrics = _METRICS.get()
    if metrics is not None and key in metrics:
        metrics[key] += max(0, int(amount or 0))


def record_model_response(response, cost_multiplier=1.0):
    usage = getattr(response, "usage_metadata", None)
    input_tokens = getattr(usage, "prompt_token_count", 0) or 0
    output_tokens = getattr(usage, "candidates_token_count", 0) or 0
    add("gemini_input_tokens", input_tokens)
    add("gemini_output_tokens", output_tokens)
    try:
        input_rate = float(os.environ.get(
            "GEMINI_INPUT_USD_PER_MILLION_TOKENS", "0.75") or 0)
        output_rate = float(os.environ.get(
            "GEMINI_OUTPUT_USD_PER_MILLION_TOKENS", "3.75") or 0)
    except ValueError:
        input_rate = output_rate = 0
    micro_usd = round(
        (input_tokens * input_rate + output_tokens * output_rate)
        * max(0.0, float(cost_multiplier))
    )
    add("estimated_cost_microusd", micro_usd)


def record_model_call():
    add("gemini_calls")


def snapshot():
    return dict(_METRICS.get() or {})
