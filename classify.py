"""Manual smoke test for gemini_client.classify()."""
import argparse
import logging

from gemini_client import classify

TEST_EMAIL = {
    "from": "nicholas.reyes@gmail.com",
    "subject": "Interested in the soccer program",
    "body": "Hi The Account Owner, my name is Nicholas and I'm a class of 2028 "
            "midfielder from New Jersey. I'd love to learn more about your "
            "program and any camps you have coming up.",
}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Run one seeded classifier check.")
    parser.add_argument("--live", action="store_true",
                        help="Required acknowledgement that this calls Gemini")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("--live is required")
    logging.basicConfig(level=logging.INFO)

    result = classify(TEST_EMAIL)
    print(result)
    print("Category is:", result["category"])


if __name__ == "__main__":
    main()
