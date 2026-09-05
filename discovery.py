"""Taxonomy discovery: sample an inbox, ask Gemini to propose categories,
write the proposals to a private review file.

Discovery is the most data-exposing step in the tool, so it is deliberately
the most restrained:

  * It reads Gmail with format="metadata" and requests only Subject and From.
    Message BODIES are never fetched, so they cannot be sent anywhere.
  * Only subjects reach Gemini, truncated, with email addresses redacted out
    of them. The sender is reduced to a coarse hint (automated / external)
    rather than an address.
  * The sample is capped. An uncapped scan would be both a quota and a
    data-exposure problem.

Discovery grants nothing. It never creates a label, never drafts, never
writes to Gmail, and never emits a confirmation - proposals are input to the
owner's review, and the confirmation artifact is something only a human
creates afterwards. Model output reaches the review file only through
taxonomy.build_taxonomy, which sanitizes and validates every name.
"""
import json
import os
import re

import gemini_client
from gmail_common import UNITS_MESSAGES_GET, UNITS_MESSAGES_LIST
from gmail_reader import get_header
from message_safety import assess_delivery_headers, opaque_id
from taxonomy import build_taxonomy, render_review_sheet
from gmail_retry import gmail_execute

# Hard ceiling regardless of what a caller asks for: discovery is a survey,
# not a full read of the mailbox.
MAX_SAMPLE = 400
DEFAULT_SAMPLE = 150
MAX_SUBJECT_CHARS = 120
MAX_PROPOSED_CATEGORIES = 12

REVIEW_FILE_VERSION = 1

# Headers fetched purely to classify a message as automated. They are used
# locally to compute one boolean; none of their contents are sent to Gemini.
# Fetching only Subject and From left bulk detection almost blind, so
# marketing blasts were being labelled as person-sent in the model payload.
SAMPLE_HEADERS = [
    "Subject", "From", "Auto-Submitted", "Precedence",
    "List-Unsubscribe", "X-Auto-Response-Suppress",
]

EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

DISCOVERY_PROMPT = """You are helping organize one person's email inbox.

Below are subject lines from a sample of their recent mail, each tagged with
whether it came from an automated sender.

Propose between 3 and {max_categories} categories that describe what this
inbox actually contains. Base them only on what you see.

Respond as strict JSON, nothing else:

{{"categories": [
  {{"name": "short name",
    "description": "one sentence",
    "examples": ["a subject line you saw", "another"]}}
]}}

Rules:
- Names must be plain descriptive words. No slashes, no punctuation.
- Every example must be copied from the sample below.
- Do not invent categories for mail you cannot see.

Sample:
{sample}
"""


def redact_subject(subject):
    """Strip email addresses out of a subject and truncate it.

    Subjects routinely carry addresses and names. Discovery only needs the
    shape of the mail, so addresses are removed before anything is sent.
    """
    text = EMAIL_IN_TEXT.sub("[address]", str(subject or "")).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:MAX_SUBJECT_CHARS]


def sample_inbox(service, query, throttle, max_messages=DEFAULT_SAMPLE,
                 own_address=""):
    """Collect redacted subject samples. Metadata only - no bodies.

    Returns a list of {"subject", "automated", "id"} records. The id is an
    opaque hash, so the sample carries no Gmail message id either.
    """
    limit = max(1, min(int(max_messages), MAX_SAMPLE))

    throttle.consume(UNITS_MESSAGES_LIST)
    listing = gmail_execute(service.users().messages().list(
        userId="me", q=query, maxResults=limit
    ))

    samples = []
    for stub in (listing.get("messages") or [])[:limit]:
        throttle.consume(UNITS_MESSAGES_GET)
        message = gmail_execute(service.users().messages().get(
            userId="me", id=stub["id"], format="metadata",
            metadataHeaders=SAMPLE_HEADERS,
        ))
        delivery = assess_delivery_headers(
            {name.lower(): get_header(message, name)
             for name in SAMPLE_HEADERS},
            own_address=own_address,
        )
        samples.append({
            "id": opaque_id(stub["id"]),
            "subject": redact_subject(get_header(message, "Subject")),
            "automated": delivery["status"] == "automated",
        })
    return samples


def render_sample(samples):
    """The exact text sent to Gemini. Subjects only."""
    lines = []
    for entry in samples:
        tag = "automated" if entry["automated"] else "person"
        subject = entry["subject"] or "(no subject)"
        lines.append(f"- [{tag}] {subject}")
    return "\n".join(lines)


def _call_model(prompt, model=None):
    """One Gemini call, reusing the shared client, throttle, and retries."""
    return gemini_client.generate_text(prompt, model=model)


def parse_proposals(raw_text):
    """Parse the model's JSON reply into raw proposal dicts.

    Tolerant of a fenced code block, strict about everything else. Returns
    [] rather than raising, so a malformed reply becomes "no proposals" and
    the caller reports that instead of writing junk.
    """
    text = (raw_text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(document, dict):
        return []
    categories = document.get("categories")
    if not isinstance(categories, list):
        return []

    proposals = []
    for entry in categories[:MAX_PROPOSED_CATEGORIES]:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        examples = entry.get("examples")
        # Only these three fields are carried forward. A "label" key in the
        # model's reply is deliberately dropped rather than validated: the
        # model proposes what the mail IS, never what a Gmail label should be
        # called. Label names are the owner's choice at setup time, so model
        # text has no path to becoming one.
        proposals.append({
            "name": name,
            "description": entry.get("description", "")
            if isinstance(entry.get("description"), str) else "",
            "examples": [e for e in (examples or []) if isinstance(e, str)]
            if isinstance(examples, list) else [],
        })
    return proposals


def build_prompt(samples):
    """The exact text that would be sent to Gemini for this sample.

    Exposed so a caller can show it to the owner before any network call.
    propose_taxonomy uses this same function, so what is previewed is what
    is sent - a separate rendering could drift from the real payload.
    """
    return DISCOVERY_PROMPT.format(
        max_categories=MAX_PROPOSED_CATEGORIES,
        sample=render_sample(samples),
    )


def propose_taxonomy(samples, model_fn=_call_model, existing_labels=()):
    """Ask the model for categories, then sanitize every name.

    Model output reaches a caller only via taxonomy.build_taxonomy, which
    enforces slug rules, reserved Gmail names, and label collisions. Nothing
    here bypasses that.
    """
    if not samples:
        raise ValueError("discovery needs at least one sampled message")

    prompt = build_prompt(samples)
    raw = model_fn(prompt)
    proposals = parse_proposals(raw)
    if not proposals:
        raise ValueError(
            "the model returned no usable categories; re-run discovery "
            "rather than proceeding without a taxonomy"
        )
    return build_taxonomy(proposals, existing_labels=existing_labels)


def build_review_document(account, taxonomy, sample_size):
    """The review file's contents.

    Deliberately NOT shaped like a confirmation artifact: it has no
    'confirmed_categories' key and carries a status of 'proposed'. Confirming
    is a separate act a human performs; discovery must never produce
    something that could be mistaken for approval.
    """
    return {
        "version": REVIEW_FILE_VERSION,
        "status": "proposed",
        "account": account,
        "sample_size": sample_size,
        "categories": [
            {
                "slug": entry["slug"],
                "display": entry["display"],
                "description": entry["description"],
                "examples": entry["examples"],
                "digest": entry["digest"],
            }
            for entry in taxonomy
        ],
        "note": (
            "These are proposals, not approvals. Drafting stays blocked for "
            "every category until you create a taxonomy confirmation "
            "artifact naming the categories you accept."
        ),
    }


def write_review_file(document, path):
    """Write the review file owner-only, refusing to clobber an existing one."""
    if os.path.exists(path):
        raise FileExistsError(
            f"{path} already exists; discovery never overwrites a review "
            "file. Move it aside or choose another path."
        )
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, 0o600)
    return path


def review_text(document, taxonomy):
    """Human-readable review output."""
    header = (
        f"Sampled {document['sample_size']} messages from "
        f"{document['account']}.\n"
    )
    return header + "\n" + render_review_sheet(taxonomy)
