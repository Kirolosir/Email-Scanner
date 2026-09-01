"""Offline-first batch classifier demonstration.

The default uses deterministic seeded results and no network. Pass ``--live``
to spend Gemini quota and compare the configured models.
"""
import argparse
import logging

import gemini_client
from gemini_client import classify
from test_emails import TEST_EMAILS

MODELS = ["gemini-3.6-flash", "gemini-3.5-flash-lite"]

STUB_RESULTS = [
    ("recruit_intro", "2027"), ("recruit_intro", "2028"),
    ("recruit_update", "unknown"), ("parent", "unknown"),
    ("camp_inquiry", "unknown"), ("other", "unknown"),
    ("other", "unknown"), ("other", "unknown"),
]

COLUMNS = [
    ("#", 3),
    ("Subject", 38),
    ("Category", 15),
    ("Grad Yr", 8),
    ("Reason", 60),
]


def truncate(text, width):
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def print_row(values, columns=COLUMNS):
    cells = [truncate(str(v), w).ljust(w) for v, (_, w) in zip(values, columns)]
    print(" | ".join(cells))


def run_batch(model, live=True):
    """Classify every TEST_EMAILS entry with `model`.

    Returns a list of (email, result) pairs; result is None if classify()
    raised after exhausting its own retries.
    """
    results = []
    for index, email in enumerate(TEST_EMAILS):
        if not live:
            category, grad_year = STUB_RESULTS[index]
            results.append((email, {
                "category": category,
                "grad_year": grad_year,
                "reason": "seeded offline demonstration",
            }))
            continue
        try:
            result = classify(email, model=model)
        except RuntimeError as e:
            print(f"  classify failed after retries for {email['subject']!r}: {e}")
            result = None
        results.append((email, result))
    return results


def print_table(model, results):
    print(f"\n=== {model} ===")
    print_row([name for name, _ in COLUMNS])
    print_row(["-" * w for _, w in COLUMNS])
    for i, (email, result) in enumerate(results, start=1):
        if result is None:
            print_row([i, email["subject"], "ERROR", "-", "classify failed after retries"])
        else:
            print_row([
                i,
                email["subject"],
                result.get("category", "unknown"),
                result.get("grad_year", "-"),
                result.get("reason", ""),
            ])


def print_comparison(all_results):
    """One row per email, one column per model, category only - for
    eyeballing where models disagree, especially on the ambiguous cases."""
    print("\n=== Category comparison ===")
    header = ["#", "Subject"] + list(all_results.keys())
    widths = [3, 38] + [max(18, len(m)) for m in all_results.keys()]
    cols = list(zip(header, widths))
    print_row(header, cols)
    print_row(["-" * w for w in widths], cols)

    for i, email in enumerate(TEST_EMAILS, start=1):
        row = [i, email["subject"]]
        for model in all_results:
            _, result = all_results[model][i - 1]
            row.append(result.get("category", "unknown") if result else "ERROR")
        print_row(row, cols)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Classify seeded emails offline, or use Gemini explicitly."
    )
    parser.add_argument("--live", action="store_true",
                        help="Make real Gemini API calls")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.WARNING)

    all_results = {}
    models = MODELS if args.live else ["offline-stub"]
    for model in models:
        gemini_client.reset_call_count()
        results = run_batch(model, live=args.live)
        all_results[model] = results
        print_table(model, results)
        print(f"\n{model}: {gemini_client.get_call_count()} API calls for "
              f"{len(TEST_EMAILS)} emails")

    print_comparison(all_results)


if __name__ == "__main__":
    main()
