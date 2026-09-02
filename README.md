# Email Drafting Tool

This is a Python tool for sorting a Gmail inbox and saving reply drafts. It
never sends mail. The person using the account opens each draft in Gmail and
decides whether to edit, send, or delete it.

## What it does

The project has two workflows.

`campaign.py` handles a one-time message sent to a known group, such as a
clinic announcement. It reads an existing Gmail label, groups messages by
sender address, and uses the newest thread for each person. This prevents ten
emails from the same recruit from producing ten copies of the same draft.

A protected campaign cannot create drafts from an unreviewed list. The tool
first produces the recipient list for inspection. A separate approval file
records the Gmail account, label, and addresses that were approved. Every
created draft ID is written to a private log. If the run needs to be undone,
the rollback command moves only those drafts to Trash.

`triage.py` and `daily_triage.py` handle regular inbox mail. The first run can
look back about two months. Later runs use a three-day overlap and a local
journal so delayed mail is still found without creating another draft for a
message that was already handled.

Triage assigns human messages to categories configured for that account, then
adds the matching Gmail labels. Existing labels are left alone. Mailing lists,
bounces, automatic replies, unsafe reply addresses, and malformed messages are
filtered before classification when the headers make that possible. Messages
with uncertain or conflicting results go to the Needs Review label.

Drafting is configured one category at a time. A category may use an approved
fixed template, allow a new reply to be generated from the current message, or
create no draft. Fixed templates are approved by content hash, so changing the
text cancels the old approval. Generated replies require a separate approval
for the Gmail account and category. They also include a warning for the account
owner to review the wording. If an approval file is missing or does not match,
the tool stops before generating a reply.

Recruiting-year labels have their own check. A classification alone cannot add
one. The sender must be a recruit, the category must be relevant, confidence
must be high, and the current message must contain matching year evidence.
Quoted replies, signatures, dates, telephone numbers, and unrelated numbers do
not count. The same rule applies whether or not a reply draft is created.

Google's `gmail.modify` scope technically permits sending email, but this tool does not send and enforces that boundary through application code and tests, not through the OAuth permission itself.

## Offline tests

Create the virtual environment and install the dependencies described in the
detailed guide. From the project directory, run:

```sh
.venv/bin/python demo_triage_flow.py
.venv/bin/python demo_daily_triage.py
.venv/bin/python demo_classify_batch.py
.venv/bin/python -m pytest -q
```

The demos use synthetic messages, fake Gmail objects, and stub classifiers.
They do not connect to Gmail, Gemini, OAuth, or the hosted authorization
service. The test suite checks the no-send rule, add-only labels, approval
binding, recruiting-year evidence, duplicate prevention, rollback behavior,
and the hosted authorization code. A passing test run checks the local code;
it does not grant access to a Gmail account.

Full setup, safety architecture, and rollout details: see [DETAILS.md](DETAILS.md).
