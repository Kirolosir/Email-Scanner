"""Explicit live smoke check for Gemini; never runs at import time."""
import argparse

from gemini_client import MODEL, get_client, get_text


def main(argv=None):
    parser = argparse.ArgumentParser(description="Make one live Gemini smoke call.")
    parser.add_argument("--live", action="store_true",
                        help="Required acknowledgement that this uses the network")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("--live is required")
    response = get_client().models.generate_content(
        model=MODEL, contents="Say hello in exactly five words."
    )
    print(get_text(response))


if __name__ == "__main__":
    main()
