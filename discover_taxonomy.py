"""Propose an inbox taxonomy for the account owner to review.

Reads a sample of Gmail metadata and asks Gemini to name the categories it
sees. Writes proposals to a private review file. Grants nothing: no label is
created, no draft is made, nothing is written to Gmail, and no confirmation
is emitted.

Contacting Gmail and Gemini requires an explicit --live acknowledgement, so
an accidental invocation costs nothing. Without it, --samples-file replays a
local sample for offline inspection.

Usage:
    python discover_taxonomy.py --account you@example.edu \\
        --output review/proposed-taxonomy.json --live

    python discover_taxonomy.py --account you@example.edu \\
        --output /tmp/review.json --samples-file samples.json
"""
import argparse
import json
import sys

import discovery
from gmail_common import QuotaThrottle

DEFAULT_QUERY = "newer_than:2m -in:spam -in:trash -in:sent -in:drafts"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Propose inbox categories for owner review. "
                    "Creates no labels and no drafts."
    )
    parser.add_argument("--account", required=True,
                        help="The Gmail address being surveyed")
    parser.add_argument("--output",
                        help="Private review file path (never overwritten). "
                             "Not needed with --show-prompt, which writes "
                             "nothing")
    parser.add_argument("--query", default=DEFAULT_QUERY,
                        help="Gmail search selecting the sample")
    parser.add_argument("--max-sample", type=int,
                        default=discovery.DEFAULT_SAMPLE,
                        help=f"Messages to sample "
                             f"(hard ceiling {discovery.MAX_SAMPLE})")
    parser.add_argument("--samples-file", metavar="FILE",
                        help="Replay a local sample instead of reading Gmail")
    parser.add_argument("--token-path", help="Separate Gmail token file")
    parser.add_argument("--live", action="store_true",
                        help="Required for ANY network call (Gmail read and "
                             "Gemini). Without it nothing leaves this machine")
    parser.add_argument("--show-prompt", action="store_true",
                        help="Print the exact text that would be sent to "
                             "Gemini, then stop. Makes no model call")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip writing the review file. Does NOT prevent "
                             "the Gmail read or the Gemini call")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    # --live gates every network call. --show-prompt stops before the model,
    # so a local sample can be inspected with no network at all.
    # --output is only meaningful for a run that writes a review file.
    if not args.show_prompt and not args.output:
        parser_error = ("--output is required unless --show-prompt is used")
        print(f"discover_taxonomy.py: error: {parser_error}")
        return 2

    offline_preview = args.show_prompt and bool(args.samples_file)
    if not args.live and not offline_preview:
        print("Refusing to contact Gmail or Gemini without --live.")
        print("For a no-network preview of exactly what would be sent, use:")
        print("  --samples-file FILE --show-prompt")
        return 2

    if args.samples_file:
        with open(args.samples_file, encoding="utf-8") as handle:
            samples = json.load(handle)
        model_fn = discovery._call_model
    else:
        # Imported here so --help and offline runs never touch auth.
        from gmail_auth import get_gmail_service

        service = get_gmail_service(token_path=args.token_path)
        throttle = QuotaThrottle()
        print(f"Sampling up to {args.max_sample} messages "
              f"(metadata only, no bodies)...")
        samples = discovery.sample_inbox(
            service, args.query, throttle,
            max_messages=args.max_sample, own_address=args.account,
        )
        model_fn = discovery._call_model

    if not samples:
        print("No messages matched the sample query; nothing to propose.")
        return 1

    if args.show_prompt:
        # Stop here. Nothing has been sent to Gemini and nothing will be.
        print(f"\nSampled {len(samples)} messages. This is the exact text "
              "that would be sent to Gemini:\n")
        print("-" * 60)
        print(discovery.build_prompt(samples))
        print("-" * 60)
        print("\nNo model call was made. Re-run with --live and without "
              "--show-prompt to actually request proposals.")
        return 0

    print(f"Sampled {len(samples)} messages. Asking for category proposals...")
    try:
        taxonomy = discovery.propose_taxonomy(samples, model_fn=model_fn)
    except ValueError as exc:
        print(f"Discovery error: {exc}")
        return 1

    document = discovery.build_review_document(
        args.account, taxonomy, len(samples)
    )
    print()
    print(discovery.review_text(document, taxonomy))

    if args.dry_run:
        print("Dry run - no review file written.")
        return 0

    try:
        path = discovery.write_review_file(document, args.output)
    except FileExistsError as exc:
        print(f"Discovery error: {exc}")
        return 1

    print(f"Wrote {path} (mode 0600).")
    print("These are proposals. Drafting stays blocked for every category "
          "until you create a taxonomy confirmation artifact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
