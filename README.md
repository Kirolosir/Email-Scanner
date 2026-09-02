# Email Drafting Tool

This project helps a coach organize a busy Gmail inbox and prepare replies
without automatically sending anything. It supports two related workflows.

The campaign workflow finds messages under an existing Gmail label, groups
them by normalized sender address, and selects the newest thread for each
person so the same recruit does not receive duplicate drafts. Before a
protected campaign can create drafts, a human must review and approve the
exact recipient list. Drafts are replies on the existing threads. Each created
draft is recorded immediately in a private log, and an explicit rollback can
move only those recorded drafts to Gmail Trash.

The triage workflow examines incoming messages, classifies legitimate human
mail into an account-specific set of categories, and adds existing Gmail
labels without removing any labels already present. An initial run can cover
about two months of Inbox mail. Later daily runs use an overlapping window and
a private journal so late messages are not missed and completed messages are
not processed twice. Automated mail, mailing lists, bounces, unsafe reply
addresses, malformed messages, uncertain classifications, and conflicting
evidence are suppressed or routed to Needs Review.

For categories whose owner has explicitly enabled drafting, replies can use
either fixed reviewed templates or message-specific AI-generated wording.
Template wording is tied to a digest, so editing it invalidates its approval.
AI drafting is approved separately for the exact Gmail account and categories,
and every generated draft receives a non-configurable warning that it is
unreviewed. Missing or invalid approval fails closed before reply generation.
The account owner must read, edit, send, or discard every draft manually.

Recruiting-year labels receive an additional safeguard. The model cannot apply
a protected year label by itself: the sender and category must qualify, the
classification must be high confidence, and deterministic evidence in the
cleaned current message must independently support the same year. Dates,
telephone numbers, signatures, and quoted history are not accepted as that
evidence. Labels are add-only, manual drafts are never overwritten, and one
message failure does not stop the rest of a run.

**Google’s `gmail.modify` scope technically permits sending email, but this tool does not send and enforces that boundary through application code, static tests, previews, approvals, and logs—not through the OAuth permission itself.**

## Current Amherst IT blocker

Authorization for the Amherst mailbox is currently blocked by Google Workspace
with `Error 400: admin_policy_enforced`. That is an Amherst administrator
policy decision, not an application error. The project must not switch OAuth
clients, accounts, or scopes to work around it. No scan, label change, draft,
or scheduled job should run against the Amherst account until Amherst IT has
approved the application and authorization succeeds for the exact intended
address.

Approval for Gmail access also does not automatically approve sending recruit
message content to Gemini. That data-processing question requires separate
institutional approval, particularly because recruiting correspondence may
involve minors. Until both questions are resolved, development and live
testing remain limited to synthetic data and the personal test account.

## Offline tests

Create the virtual environment and install the dependencies as described in
the detailed guide, then run:

```sh
.venv/bin/python demo_triage_flow.py
.venv/bin/python demo_daily_triage.py
.venv/bin/python demo_classify_batch.py
.venv/bin/python -m pytest -q
```

The demonstrations use fake Gmail data, synthetic messages and templates, and
stub classifiers. They do not contact Gmail, Gemini, OAuth, or the hosted
broker. The test suite includes the static no-send audit, add-only label
checks, approval and account-binding checks, protected-label evidence tests,
draft idempotency and rollback tests, and broker safety tests. Passing these
checks proves the offline implementation is internally consistent; it does not
authorize a real mailbox or override institutional policy.

Full setup, safety architecture, and rollout details: see [DETAILS.md](DETAILS.md).
