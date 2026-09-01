"""Proves Gmail reading works end-to-end: authorizes against the cached
token, lists messages under a given label, and prints a clean plain-text
body for each. Read-only - does not create drafts or send anything.

LIVE SCRIPT, not a unit test. It authorizes against the real account and
makes real API calls, so it is named check_* rather than test_* to keep
pytest from collecting it. (It also reads sys.argv at import time, which
would make pytest's own flags blow up its argument parsing.)

Usage: python check_gmail_read.py [LABEL_NAME] [MAX_RESULTS] --live
"""
import argparse

from gmail_auth import get_gmail_service
from gmail_reader import get_header, get_message, get_plain_text_body, list_message_ids

def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit live Gmail read check.")
    parser.add_argument("label", nargs="?", default="INBOX")
    parser.add_argument("max_results", nargs="?", default=5, type=int)
    parser.add_argument("--live", action="store_true",
                        help="Required acknowledgement that this reads Gmail")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("--live is required")
    service = get_gmail_service()

    message_ids = list_message_ids(
        service, args.label, max_results=args.max_results
    )
    print(f"Found {len(message_ids)} message(s) under label {args.label!r}\n")

    for message_id in message_ids:
        message = get_message(service, message_id)
        subject = get_header(message, "Subject")
        sender = get_header(message, "From")
        body = get_plain_text_body(message)

        print(f"--- {message_id} ---")
        print(f"From:    {sender}")
        print(f"Subject: {subject}")
        print(f"Body:    {body[:300]!r}")
        print()


if __name__ == "__main__":
    main()
