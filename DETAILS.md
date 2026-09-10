# Full Setup, Safety Architecture, and Rollout Details

This file contains the complete operating, approval, deployment, safety, and
rollout reference. For the short project overview and offline test commands,
see [README.md](README.md).

## Setup and authorization

Use Python 3.10 or newer and a dedicated test account first:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
chmod 600 .env credentials.json token.json
```

Enable the Gmail API, create a Desktop OAuth client, and save the downloaded
file as `credentials.json`. The optional desktop authorization fallback is:

```sh
.venv/bin/python gmail_auth.py --authorize
```

Google opens its own sign-in and consent page. This application never sees the
Gmail password. For a second account, keep a separate ignored token and pin the
exact address you expect:

```sh
.venv/bin/python gmail_auth.py --authorize \
  --token-path tokens/owner.json \
  --expected-account "owner@example.edu"
```

Authorizing the account owner's mailbox currently fails with `Error 400:
admin_policy_enforced`. That's their Workspace administrator's decision, not a
bug on our side. Don't switch clients, accounts, or scopes to get around it.
Until IT approves the OAuth application and authorization succeeds against the
exact address, nothing runs against that account: no setup, no scan, no label,
no draft, no schedule.

There's a hosted OAuth broker that lets an account owner authorize from their
own device. It's been run end to end with a personal test account, but it has
never produced a credential for the owner's mailbox, and it doesn't work around
the administrator block. See
[Hosted OAuth broker](#hosted-oauth-broker-deployed-test-service). The desktop
flow above stays available either way.

Secret files, tokens, logs, caches, state, and virtual environments are all
gitignored. On POSIX systems token and state files are mode 0600 and their
private directories are 0700. Changing OAuth scopes forces a deliberate
re-authorization, so don't do it in the middle of a campaign run.

## No-send boundary

Google's `gmail.modify` scope technically permits sending email. This project
does not send, and the boundary is enforced by code review and tests rather
than by the OAuth permission. Production code contains no Gmail send call.
The static source/AST audit rejects direct, dynamic, aliased, and obscured send
operations and audits every production module.

The only permitted Gmail mutations are `drafts().create()`, add-only
`messages().modify()` label changes, `labels().create()` inside the dedicated
onboarding command, and `messages().trash()` during explicit campaign rollback.
Everything else is rejected. Triage never removes a label, modifies an existing
draft, or sends a draft. Every generated reply remains an ordinary editable,
unsent Gmail draft until the account owner acts on it manually.

## Urgent campaign

`YEAR_LABEL` is the exact campaign label. Deduplication works on the normalized
sender address, and you can supply known aliases explicitly through
`aliases.example.txt`. No AI is involved in deciding who is the same person.

Start with a test account and a dry run:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python campaign.py "YEAR_LABEL" body.txt \
  --aliases aliases.example.txt --exclude exclusions.example.txt \
  --limit 2 --dry-run
```

`body.txt` holds the wording the account owner supplied, including the direct
registration links. Leave it alone unless they approve an edit. A full scan
covers roughly 9,000 messages and takes 30 to 40 minutes at current quota
pacing. `--limit` caps drafts after deduplication. It won't shorten the scan,
which has to finish before the newest thread per sender can be picked
reliably.

Every created draft ID is flushed to `draft-logs/` as it happens. To roll back
one recorded run, preview it first:

```sh
.venv/bin/python campaign.py --undo draft-logs/campaign-YYYYMMDD-HHMMSS.log --dry-run
.venv/bin/python campaign.py --undo draft-logs/campaign-YYYYMMDD-HHMMSS.log
```

Rollback asks for its own confirmation, then moves those drafts to Trash. It
never deletes anything permanently.

`YEAR_LABEL` is protected. You can dry-run without an approval file to look
around, but the run prints `UNREVIEWED` and real draft writes stay blocked.
Before a real run, build a private recipient audit. The audit reads Gmail and
calls Gemini for normal unique recipients, and it has no Gmail write operation
at all:

```sh
.venv/bin/python campaign_audit.py "YEAR_LABEL" \
  --token-path tokens/owner.json \
  --aliases aliases.example.txt \
  --output audit-reports/YEAR_LABEL-REVIEW.json
```

Because the report lists recipient addresses, its directory is mode 0700 and
the file is 0600. It stores no subjects, bodies, credentials, tokens, or
free-form model reasoning. Note that `candidate_for_human_approval` is a
recommendation and nothing more. The account owner still has to review the
population themselves and write a separate approval file, modelled on
`campaign-approval.example.json`.

Use `--max-scan` and `--limit` for the first audit pilot. Auditing roughly
2,000 unique recipients can run for several hours at six seconds between model
calls, before you count Gmail latency or retries, and it consumes paid API
quota.

```json
{
  "version": 1,
  "account": "owner@example.edu",
  "label": "YEAR_LABEL",
  "approved_recipients": ["reviewed-recipient@example.com"]
}
```

Keep the real file private:

```sh
chmod 600 campaign-approval.owner.json
```

At run time the campaign checks that approval against the authenticated Gmail
account and the exact label, rejects malformed, empty, or conflicting
recipients, then intersects what's left with your aliases and exclusions. A
small reviewed pilot looks like this:

```sh
.venv/bin/python campaign.py "YEAR_LABEL" body.txt \
  --token-path tokens/owner.json \
  --approval campaign-approval.owner.json \
  --aliases aliases.example.txt --exclude exclusions.example.txt \
  --limit 3 --dry-run
```

Drop `--dry-run` only once the preview looks right. There's no flag that
bypasses the protected-label gate.

## Classification and drafting modes

With no account profile supplied, the tool falls back to a legacy built-in
category list:

- `recruit_intro`
- `recruit_update`
- `video_update`
- `parent`
- `other_coach`
- `camp_inquiry`
- `administrative`
- `other`
- `unknown`

Point `--account-config FILE` at a real profile and that list is replaced by
the account owner's reviewed taxonomy. `discover_taxonomy.py` can propose
category names from redacted subject lines, but a proposal grants nothing and
creates no Gmail labels. `approve_account.py` is what records the exact
taxonomy digests the owner actually reviewed. Real files under `accounts/` and
proposals under `review/` are private and gitignored.

**What reaches Gemini.** Classification sends the safe reply metadata, the
subject, and at most 8,000 characters of the cleaned current top-posted
message. Quoted history, common signatures, and attachment contents are left
out. The current account-wide approval may classify and draft mailing-list,
bulk-precedence, auto-submitted, and auto-response-suppressed messages when a
safe reply address still exists. Those headers remain recorded as delivery
advisories. Spam, trash, sent mail, and existing drafts are excluded by the
Gmail query. Bounce endpoints, final no-reply targets, self-replies, malformed
addresses, ambiguous Reply-To values, and messages with no safe reply path
never get a new draft.

Gemini returns category, graduation year, sender type, confidence, evidence,
and a short reason, in a strict format. Anything unsupported or malformed
becomes `unknown`. Raw model output and message bodies are never logged.
Approval to touch Gmail doesn't cover any of this: sending message content to
a third-party model is a separate institutional decision, and you need it
before enabling classification.

### One-time account-wide drafting activation

For the seamless workflow, put these reviewed settings in the account profile:

```json
{
  "draft_all_replyable_messages": true,
  "fallback_category": "other"
}
```

The boolean expresses intent but grants nothing by itself. `approve_account.py`
creates a separate version 3 approval bound to the exact Gmail account and a
SHA-256 digest of the taxonomy, labels, category guidance, signature, account
guidance, fallback category, evidence rules, and protected-label permission.
Changing any of those settings invalidates the activation.

Preview the exact taxonomy and grant without writing anything:

```sh
.venv/bin/python approve_account.py \
  --account-config accounts/owner.json \
  --taxonomy-output accounts/owner-taxonomy.json \
  --ai-output accounts/owner-ai.json \
  --dry-run
```

Remove `--dry-run` when the owner is ready. The owner personally types the full
sentence printed by the command. It explicitly names the account and states the
grant the code actually implements: unsent drafts for every message with a safe
reply address outside Spam, Trash, Sent, and Drafts. Version 2 approvals retain
their narrower automated/bulk exclusion until the owner saves the current
settings. There is no `--yes` option for this activation. It is needed once
during onboarding, not for every message or scheduled run.

Every generated draft carries the hardcoded
`AI-DRAFTED - UNREVIEWED WORDING - NOT SENT` banner. Unknown, low-confidence,
or conflicting classifications use the configured `Other` label, also receive
`Needs Review`, and get a neutral acknowledgement when the return path is
safe. Generation gets at most two attempts. If both fail validation or error,
the system uses the hardcoded fact-free `Thank you for your message.` plus the
configured signature and banner. It never fabricates a recipient.

Protected-label drafting remains a separate, larger permission. Add
`--allow-protected-labels` only when intended; the confirmation then adds the
exact clause `including messages under protected labels`. That grant does not
loosen the independent evidence rules for applying the label.

### Legacy category drafting modes

Existing profiles remain compatible. When account-wide drafting is off, each
configured category gets exactly one drafting mode:

- `off`: classification and add-only labels still run, but no reply is
  generated.
- `template`: fixed wording, bound to its SHA-256 approval.
- `generic`: Gemini writes wording per message. This needs a separate
  account/category-bound `--ai-drafting-approval`, though not a template
  digest. Every generated draft carries the hardcoded
  `AI-DRAFTED - UNREVIEWED WORDING - NOT SENT` banner, and the account owner
  has to review, edit, or discard it.

Miss either the legacy mode or its approval and drafting stays off. An unapproved
generic path is rejected before generation, so no message content reaches the
generation call at all. Generic drafting never sends mail, and it never gets a
vote on whether a protected year label applies.

For a legacy per-category profile, create the taxonomy and generic-drafting
approvals offline:

```sh
.venv/bin/python approve_account.py \
  --account-config accounts/owner.json \
  --taxonomy-output accounts/owner-taxonomy.json \
  --ai-output accounts/owner-ai.json
```

The owner types the exact sentence the command prints. If generic categories
should also be allowed to draft on messages
carrying a protected label, add `--allow-protected-labels`, and the sentence
they type changes to say `including messages under protected labels`. That's a
strictly larger grant, but it doesn't loosen the local/model evidence
agreement that governs whether the label applies in the first place.

### Fixed-template mode

Templates resolve in this order:

1. `templates/<category>_<grad_year>.txt`
2. `templates/<category>.txt`

All 8 templates shipped in `templates/` are still placeholders.

In legacy mode, anything unknown, ambiguous, conflicting, malformed, or
missing a template gets `Needs Review` and no generated reply. Account-wide
mode instead uses the safe acknowledgement behavior above whenever the reply
destination itself is safe.

### Two independent gates

Swapping a placeholder for real wording does not start drafting. A template
only gets used when it is both:

1. not `[PLACEHOLDER TEMPLATE ...]` marked, and
2. explicitly approved for its exact template key.

The marker is checked first, so an approval can never unlock a placeholder.

The default fails closed. With no approval supplied, triage classifies and
labels as usual and skips only the draft, logging `template unapproved: no
reviewed approval for '<key>'` and routing the message to `Needs Review`.

Approval is per template key, never global. Approving `recruit_intro` won't
activate `parent` or `camp_inquiry`. And since `recruit_intro_2027.txt` is
different wording from `recruit_intro.txt`, it needs its own approval.

Both `triage.py` and `daily_triage.py` take the two flags below, and both go
through one enforcement point, so the scheduled 6 PM run is gated exactly like
an interactive one.

**`--template-approval FILE` (wording-bound; use this for real runs).** Pins
each approved key to the SHA-256 digest of the exact reviewed text. Edit a
template after approval and you revoke it, rather than carrying the approval
over to wording nobody has read:

```sh
.venv/bin/python triage.py "INBOX" \
  --template-approval template-approval.owner.json --limit 5 --dry-run
```

**`--templates-approved KEYS` (name-only; supervised runs only).** A
comma-separated list of keys approved for a single run. It's deliberately the
weaker of the two: it doesn't pin wording, so all it really attests is that an
operator typed the key on the command line. Fine for an interactive pilot where
someone reads every draft. Never use it for a scheduled run:

```sh
.venv/bin/python triage.py "INBOX" \
  --templates-approved recruit_intro,parent --limit 5 --dry-run
```

Both commands print the approvals they're running with, and the name-only form
adds an explicit warning that wording isn't pinned.

To build an approval artifact, take the digest of each reviewed template. This
reads one local file and makes no network call:

```sh
.venv/bin/python -c "from triage import template_digest; print(template_digest(open('templates/recruit_intro.txt', encoding='utf-8').read()))"
```

Copy the digests into a private file modelled on
`template-approval.example.json`. List only the templates someone has actually
read:

```json
{
  "version": 1,
  "account": "owner@example.edu",
  "label": "YEAR_LABEL",
  "approved_templates": {
    "recruit_intro": "sha256:dc25272e...66218"
  }
}
```

`account` is required, and it's checked against the authenticated Gmail
account. It's the same binding the campaign approval uses. An approval you
reviewed on the test account therefore can't authorize drafting in the owner's
mailbox; the run stops with `template approval account does not match the
authenticated Gmail account`. Comparison is normalized, so
`Owner <owner@example.edu>` and `OWNER@EXAMPLE.EDU` match.

`label` is optional, because the daily processor scans an inbox query rather
than one label. Leave it out and the artifact covers any label in its account.
Put it in and it's honored strictly: it has to equal the label passed to
`triage.py`, and a run that isn't targeting a single label gets refused instead
of quietly widened. That means the daily processor needs an artifact with no
`label`.

Structure is validated before any Gmail contact, so a malformed file fails
right away. The account binding is checked later, after authorization, once
there's an authenticated account to compare against. A wrong version, an empty
`approved_templates`, a non-string key, or a digest that isn't
`sha256:<64 hex>` all fail the run rather than leaving a template
unapproved-but-assumed-approved.

Keep the real file private. `template-approval*.json` is gitignored apart from
the example:

```sh
chmod 600 template-approval.owner.json
```

**What this gate does not cover.** The digest proves the wording is unchanged
since the artifact was written, and the account binding proves it was reviewed
for this mailbox. Neither proves a human actually read the text. That remains
an operator responsibility, as it does for the campaign allowlist.

## Exact label policy and bootstrap

In the legacy profile, `YEAR_LABEL` is reserved for mail actually sent by a
recruit of that class year, in a recruiting category. A generalized account
profile can define the same protected label and evidence rule through config
instead of hardcoding it into the pipeline.

The model's answer alone is never enough to apply it. Four things have to line
up: the cleaned current message contains deterministic year evidence such as
`Class of <year>`, the classifier is high confidence, and the locally extracted
year agrees with the model's. Dates, schedules, phone numbers, quoted history,
and footers don't count as evidence. A parent, another coach, an administrator,
an automated sender, a vendor, or a reporter doesn't get the label just because
their text mentions a recruit of that year. Low or medium confidence, or
evidence that contradicts itself, never applies the protected label. It routes
to Needs Review; after valid account-wide activation it may still receive a
neutral draft when its reply destination is safe.

`label-config.example.json` or the account profile holds the reviewed mapping:

- evidence-gated year labels
- category labels under a configured prefix
- a `Needs Review` label
- a hidden `Processed` label

Neither `triage.py` nor the daily processor ever creates a label. The bootstrap
command is the only module allowed to, and only for the exact labels named in
that config. It is offline by default and first prints the complete configured
set:

```sh
.venv/bin/python setup_labels.py \
  --account-config accounts/owner.json
```

Read-only comparison with Gmail requires `--live`:

```sh
.venv/bin/python setup_labels.py \
  --account-config accounts/owner.json \
  --token-path tokens/owner.json --live --dry-run
```

Creation requires both `--live` and `--apply`:

```sh
.venv/bin/python setup_labels.py \
  --account-config accounts/owner.json \
  --token-path tokens/owner.json --live --apply
```

The command displays exact existing and missing matches, then requires an
account-and-count-bound typed sentence covering the complete set. It creates at
most 100 missing configured labels, including configured evidence-gated label
names, and reuses exact existing matches. A case-only collision is refused.
Running it twice is harmless. It accepts no free-text label name, never reads
classifier output, and never renames, removes, deletes, or changes a Gmail
system label. Creating a protected label name does not apply it to any message;
the independent evidence gate still controls that later action.

## Two-month backfill and daily triage

Before classifying anything, estimate the initial workload from metadata alone.
This makes zero Gemini calls and zero Gmail writes:

```sh
.venv/bin/python daily_triage.py initial \
  --account-config accounts/owner.json \
  --taxonomy-confirmation accounts/owner-taxonomy.json \
  --ai-drafting-approval accounts/owner-ai.json \
  --token-path tokens/owner.json --estimate-only --scheduled \
  --max-scan 25 --limit 25 --max-drafts 5
```

The estimate breaks the window down into already-processed, automated,
invalid-metadata, and genuine Gemini candidates, then reports the minimum
model-spacing time at the configured six-second interval. Expect it to take
longer in practice, once Gmail latency and retries are in play.

`daily_triage.py` defaults to a dry run. Initial mode searches Inbox mail from
roughly the last two months and explicitly excludes Spam, Trash, Sent, and
Drafts:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py initial \
  --account-config accounts/owner.json \
  --taxonomy-confirmation accounts/owner-taxonomy.json \
  --ai-drafting-approval accounts/owner-ai.json \
  --max-scan 50 --limit 10 --max-drafts 3 \
  --review-report review/initial-dry-run.json --dry-run
```

Once you've reviewed a test-account preview, completed the one-time activation,
and run a small pilot, `--apply` is the explicit write gate:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py initial \
  --account-config accounts/owner.json \
  --taxonomy-confirmation accounts/owner-taxonomy.json \
  --ai-drafting-approval accounts/owner-ai.json \
  --max-scan 50 --limit 10 --max-drafts 3 \
  --review-report review/initial-pilot.json --apply
```

All `--apply` does is authorize Gmail writes. It does not create the taxonomy
confirmation, global activation, legacy template approval, or protected-label
permission. Those private artifacts must already validate. A missing or stale
global activation fails closed before reply generation.

**`--limit N` is a budget of N Gmail writes**, counting label adds and drafts
together. Not N messages, and not N classifications. One message usually costs
more than one write: a category label, sometimes `Needs Review`, the
`Processed` label, and a draft if its category drafts.

The budget is spent whole messages at a time. A message that doesn't fit is
deferred rather than half-written, because applying its category label without
`Processed` would leave the next run treating it as new. Deferred messages
aren't marked processed, so the following run picks them up, and a bounded
daily run doesn't set the same-day guard while work remains. That makes
`--limit` a throttle for a staged rollout rather than a way to skip mail.

The run prints what it spent and what it deferred:

```
Label adds:   up to 11
Drafts:       up to 0
Write budget: 11 of 12 (--limit bounds label adds plus drafts)
Deferred:     1 candidate(s) left for the next run; they were not marked processed
```

Because every message costs at least the `Processed` label, at most N messages
are fetched and classified, so N also caps Gemini calls. If a limit is too
small to afford even one message, the run says so and changes nothing rather
than stalling silently. To bound the Gmail *read* instead, use `--max-scan`.

This was previously a classification-only bound: a measured `--limit 15` run
classified 15 messages but processed 158 and wrote up to 182 labels.

`--max-drafts N` is a second, independent limit. It counts only new Gmail
drafts created in the current run. A draft already recorded in the private
journal and reconciled on restart does not spend this budget. When a new draft
would exceed the cap, that whole message is deferred: it receives no labels and
is not marked Processed. Non-drafting messages can continue within the regular
write budget. `--max-drafts 0` guarantees zero new drafts. Whole replyable
messages whose drafts do not fit are deferred without labels or a Processed
marker; messages with no safe reply address may still be labeled within the
normal write budget.

Daily mode searches a three-day overlap so late-arriving mail isn't missed:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py daily \
  --max-scan 25 --limit 25 --max-drafts 5 --dry-run
```

Three terms that are easy to confuse:

- A live `--dry-run` blocks Gmail writes. It still reads Gmail and may call
  Gemini.
- `--estimate-only` reads Gmail metadata, calls Gemini zero times, and writes
  to Gmail zero times.
- The offline demos and tests use fake Gmail and stub classifiers, and make no
  network calls at all.

The processor skips anything already carrying the `Processed` label or marked
complete in its private journal. That journal is written atomically under
`triage-state/` with owner-only permissions, and it holds IDs and statuses.
Not subjects, not senders, not bodies, not credentials, not model output.

Existing drafts on a thread are reconciled before anything new is created. A
draft written by hand, or by some other tool, is never adopted, never modified,
and never entered into a rollback log; that thread goes to Needs Review
instead. A draft this program provably created can be recovered from the
journal. And if a run is interrupted after creating a draft but before applying
the processed label, the draft log and journal are flushed immediately enough
that a restart won't duplicate it. Corrupt or unsupported state blocks the run
rather than resetting itself.

Every run also takes a crash-safe, nonblocking OS lock keyed by a private hash
of its target. A second run against the same target exits with status 75 before
it ever contacts Gmail. A PII-free status file records the last attempt and
success, counts,
safe error codes, and lock conflicts. Runtime/state/status directories are 0700
and private files are 0600.

Messages are isolated from each other, so one API or classification failure
doesn't throw away the rest of the plans. Labels are add-only. Drafts are
replies inside existing threads, and they sit there unsent until someone reads
them.

### Private review reports

`--review-report PATH` writes a versioned JSON report for either a dry run or an
applied run. It contains only counts, opaque message identifiers, category and
confidence, proposed or applied label names, draft eligibility and outcome,
and allowlisted reason codes. It never stores subjects, bodies, addresses,
draft wording, raw Gmail IDs, classifier evidence, exception text, OAuth data,
or tokens. The directory is mode 0700 and the completed file is mode 0600.

The requested path is reserved before Gmail contact and is never overwritten.
Publication uses an exclusively created private temporary file and an atomic
link. If the process is interrupted first, the clearly named
`.in-progress` marker remains instead of a malformed completed report. Use a
new filename for every run.

### Untrusted email and prompt injection

Classification and drafting prompts serialize the sender, subject, and cleaned
body as `UNTRUSTED_EMAIL_JSON`. Instructions, role markers, fake delimiters, or
JSON placed inside an email remain data. They cannot change the confirmed
taxonomy, output schema, signature, word limit, approval state, protected-label
evidence rule, or no-send boundary. Model output is still treated as untrusted:
unsupported categories normalize to unknown, protected years need independent
local evidence, and generated replies containing mail headers, account-action
claims, internal prompt disclosures, or secret disclosures are rejected.

## Prepared 6 PM macOS schedule (not installed)

`launchd/com.example.email.daily-triage.plist.example` is set up for 6:00 PM
local time and contains no secrets. launchd needs absolute paths, so replace
every `/ABSOLUTE/PATH/TO/CHECKOUT` in it with this checkout's real location
before installing. It carries `--apply --yes`, so don't install it until every
rollout gate below has passed and the one-time account activation exists.
`--yes` skips only the routine nightly write prompt; it cannot create or widen
that activation.
Scheduled mode now refuses to start unless `--max-scan`, the total-write
`--limit`, and `--max-drafts` are all supplied explicitly. The prepared files
use conservative values of 25 scanned messages, 25 Gmail writes, and five new
drafts. This validation occurs before Gmail authentication, Gemini setup, or
state changes, and `--yes` cannot bypass it.
The machine has to be awake and online. Duplicate invocations are harmless,
between the same-day guard and the processed journal. Its `--token-path`
points at `tokens/owner.json` specifically, so a scheduled run against the
owner's mailbox can't quietly fall back to `token.json`. One thing to watch:
18:00 only means the intended Eastern-time run while the Mac's system timezone
stays America/New_York.

The plist also passes `--scheduled --notify-on-failure`. Unattended output is
limited to counts, label category names, opaque identifiers, timestamps, and
safe error codes. No subjects, addresses, bodies, classifier reasoning, or
secrets. A failed run asks macOS to display one local notification containing
only the exit code, allowlisted counts and error codes, and a direction to read
the private status file. It uses `/usr/bin/osascript` without a shell and makes
no network call. Failure to display the notification is logged with fixed text
and never replaces the triage run's original exit status.

Before you ever activate it, create private scheduler logs:

```sh
mkdir -p automation-logs
chmod 700 automation-logs
touch automation-logs/daily-triage.out.log automation-logs/daily-triage.err.log
chmod 600 automation-logs/*.log
```

Copy the reviewed plist to `~/Library/LaunchAgents/`, check it with
`plutil -lint`, and enable it with `launchctl bootstrap gui/$(id -u) ...`.
Inspect it with `launchctl print gui/$(id -u)/com.example.email.daily-triage`,
and pause or remove it with `launchctl bootout gui/$(id -u) ...`. These are
instructions for whoever eventually turns it on. The project itself installs
nothing.

## Hosted OAuth broker (deployed test service)

`oauth_broker.py`, `broker_crypto.py`, `broker_client.py`, and `broker_wsgi.py`
let an account owner complete Google sign-in on their own device, with the
operator's machine out of the loop entirely. The test broker is deployed at
`https://email-scanner-hhma.onrender.com`. The local tools don't assume it's
up, and the Workspace administrator block applies to it unchanged.

The credential only ever passes through Google and the broker. The broker seals
the refresh token to a public key the operator generated locally, which means it
can encrypt but has no way to decrypt. Fully compromise the broker and what you
get is ciphertext, not a Gmail token.

### Single instance is a correctness requirement

The pending-state, invite, and pickup stores all live in the web worker's
memory. A second instance wouldn't see states minted by the first, so sign-ins
would fail intermittently and the single-use guarantees would only hold per
instance. `render.yaml` pins `numInstances: 1` and `--workers 1`, and a test
asserts both. Before going to more than one process, those stores have to move
to shared storage with the same single-use semantics.

Threads are fine. `MemoryStore.take` removes with a single `dict.pop`, so two
concurrent callbacks can't both consume the same state.

### On the free plan the real window is one sitting, not 24 hours

The deployed broker (`srv-dabdm24s728c73adbr70`, "Email Scanner") runs on
Render's free plan. Confirmed on the dashboard: Manual Scaling is 1 and
autoscaling is off. Free instances can't scale at all, so the plan itself
enforces the single-instance requirement above, over and above the
configuration.

Note that `render.yaml` declares `plan: starter`, which the running service
does not match. The blueprint was not what created it. That matters because
everything below applies to the free plan only: on starter there's no
spin-down, and a service created from the blueprint would behave differently
from the one currently deployed. Check the dashboard rather than the
blueprint when you need to know which you have.

Free instances spin down after periods of inactivity, and a spin-down wipes
everything held in memory. The invite, pending-state, and pickup stores all
live in the web worker's memory, so:

| Store | Survives a spin-down? | Consequence |
| --- | --- | --- |
| Seeded invites | Yes | Re-seeded from `BROKER_INVITE_IDS` at boot |
| Pending OAuth states | **No** | An owner who takes longer than the idle window between opening the link and finishing Google sign-in gets "this link is not valid or has already been used" |
| Sealed pickups | **No** | A credential the operator has not collected yet is **destroyed**, and `/pickup` then returns 404 exactly as though it had already been collected |

So on the free plan, treat the whole flow as one continuous sitting. Mint the
invite, have the owner sign in, and collect the credential without a long idle
gap. Both failures are silent and look identical to "already used", which is
also what a genuine replay returns, so you can't tell from the response which
one happened.

To get an actual 24-hour window, either move to a paid instance, which doesn't
spin down, or persist the pickup store. Persisting it has a cost: sealed
credentials then live somewhere other than one process's memory, and that
tradeoff deserves a decision before anyone builds it.

### Host

Deployed on Render, which builds a Python service from
`broker-requirements.txt` with no Dockerfile and defaults to one instance.
`Procfile` carries the same start command for any Procfile-style host. Some
hosts default to more than one instance; `fly launch` creates two machines.
On those, pin it to one and confirm before sending any invite, or the
single-instance requirement above is silently violated.

### Environment variables

Copy the names from `broker.env.example` into the host's environment settings.
Never commit a filled-in copy. Every variable is required, and the broker
refuses to start if any is missing or unsafe, so a misconfigured deploy fails
at boot instead of serving a broker that quietly skips a check.

| Variable | Secret | Notes |
| --- | --- | --- |
| `BROKER_CLIENT_ID` | no | From the Google OAuth client (type: Web application) |
| `BROKER_CLIENT_SECRET` | **yes** | Used only in the server-side token exchange; never appears in any response, redirect, or log |
| `BROKER_REDIRECT_URI` | no | Must be `https` and match the registered redirect URI exactly |
| `BROKER_OPERATOR_PUBLIC_KEY` | no | Hex public half of the operator keypair. Wrong value means credentials nobody can open |
| `BROKER_OPERATOR_BEARER` | **yes** | Authorizes `/pickup`; at least 32 characters |
| `BROKER_INVITE_IDS` | **yes-ish** | Comma-separated invite ids. A stolen invite lets someone burn it, not read the owner's mail |

### 1. Generate the operator keypair

Run on your own machine. The private half never leaves it.

```sh
.venv/bin/python broker_client.py keygen --private-out broker-operator.key
```

It prints the public half. That goes in `BROKER_OPERATOR_PUBLIC_KEY`. Hold on
to `broker-operator.key` at mode 0600. Lose it and the sealed credential is
gone for good; there's no way to ask the broker for a second copy.

Generate the pickup credential while you're here:

```sh
.venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 2. Mint an invite

Invites are created offline and seeded through configuration. Nothing reachable
over the network can create one, so there's no admin endpoint to defend. A
shell on the host wouldn't help an attacker either, since the stores live in
the web worker's memory and a shell is a different process.

```sh
.venv/bin/python broker_client.py mint-invite --broker-url https://your-broker-host.example.com
```

Add the printed id to `BROKER_INVITE_IDS` and **restart the instance** so it
seeds. Restarting also clears any sign-in already in flight, so restart before
sending the link, not during.

### 3. Send the owner their link

The command prints it:

```
https://your-broker-host.example.com/start/<invite-id>
```

The link is single use. The invite id gets re-seeded from configuration at every
boot, but the sign-in it starts doesn't, so on the free plan have the owner open
it and finish while you're still with them. An idle spin-down loses the pending
state. They sign in with Google and land on a plain confirmation page. It shows
no token and no code, and says outright that nothing was sent from their account
and no message was read during sign-in.

If they abandon it, or the state's 10-minute window lapses, mint a fresh invite.
Nothing here is reusable, by design.

### 4. Retrieve the sealed credential

```sh
export BROKER_OPERATOR_BEARER='<the value you generated in step 1>'

.venv/bin/python broker_client.py collect \
  --url https://your-broker-host.example.com/pickup/<invite-id> \
  --private broker-operator.key \
  --token-out tokens/owner.json
```

The bearer is read from the environment, never from the command line, because
arguments are visible to every process via `ps`.

Pickup happens once. A successful fetch deletes the ciphertext. A *failed*
authorization doesn't consume it, so a wrong bearer can't destroy the
credential. `collect` also refuses to overwrite an existing token file.

From there, `tokens/owner.json` is an ordinary credential, and the existing
`--token-path` flags use it unchanged.

### Before standing any of this up

- The Google OAuth client has to be type **Web application**, with the exact
  `BROKER_REDIRECT_URI` registered. The desktop client `gmail_auth.py` uses
  won't work here.
- The `admin_policy_enforced` block applies to the broker just as it does to
  the desktop flow. The broker doesn't route around an administrator decision,
  and must not be used to try.
- There's no rate limiting in the app. Put it in front.
- TLS termination is the host's job. The app enforces `https` and honours
  `X-Forwarded-Proto`, so a hosting proxy doesn't make it reject every request.
- Sealed ciphertext is held in memory only. On the free plan an idle
  spin-down destroys it. Collect it in the same sitting; there is no 24-hour
  window. See
  [On the free plan the real window is one sitting](#on-the-free-plan-the-real-window-is-one-sitting-not-24-hours).

## Readiness checker

The readiness command runs offline by default. It executes the full test suite,
runs the static no-send audit separately, validates the account-bound taxonomy
and drafting approvals, checks private token permissions, and validates any
optional campaign artifacts. It contacts nothing: not Gmail, not Gemini, not
OAuth, not the broker.

```sh
.venv/bin/python check_readiness.py \
  --account-config accounts/owner.json \
  --taxonomy-confirmation accounts/owner-taxonomy.json \
  --ai-drafting-approval accounts/owner-ai.json \
  --token-path tokens/owner.json
```

An offline pass prints `OFFLINE READY`, which deliberately stops short of
claiming the token belongs to the configured account or that the Gmail labels
exist. Once you have explicit approval for a network read, add `--live`. Live
mode refreshes the existing token in memory if it has to, then reads the Gmail
profile and label list and nothing else. It never starts OAuth, never persists
the refreshed token, never reads a message, and performs zero Gmail writes:

```sh
.venv/bin/python check_readiness.py \
  --account-config accounts/owner.json \
  --taxonomy-confirmation accounts/owner-taxonomy.json \
  --ai-drafting-approval accounts/owner-ai.json \
  --token-path tokens/owner.json \
  --live
```

It only contacts the hosted broker if you pass both `--live` and an explicit
`--broker-health-url`. To include a campaign, supply `--campaign-label`,
`--campaign-approval`, and `--campaign-body` together. Incomplete inputs make
the result not ready, and so does any check that can't finish.

## Prepared account configuration (not activated)

`account-config.prepared.json` holds drafted category wording guidance for the
account owner's eventual mailbox. It's inert, kept in the repository so it can
be reviewed before anyone uses it. On its own it grants nothing: no approval
artifact is bound to it, it declares no protected label, and every drafting
mode in it stays inert until the steps in its `_comment` are done.

Two separate institutional approvals have to land before it goes live, and the
first doesn't imply the second:

1. **Gmail OAuth.** The last attempt came back `Error 400:
   admin_policy_enforced`, which is a Workspace policy decision. Ask for the
   current ticket status. Don't assume it's resolved, and don't work around it.
2. **Gemini data processing.** Sending recruit email content, which may involve
   minors, to a third-party model is its own decision. Gmail access doesn't
   cover it. Gemini also runs on a personal API key right now, which is a
   governance problem to fix before any production use.

Even after both, the account still needs taxonomy discovery run against it,
since these categories were drafted rather than discovered. Then the owner
personally runs `approve_account.py`, and an account-bound AI-drafting approval
gets created.

`YEAR_LABEL` is deliberately missing from the prepared config. Adding it takes
a `protected_labels` entry plus an `evidence_gated_labels` rule. AI drafting on
protected-label messages needs `allow_protected_labels` on top of that, and the
longer confirmation phrase ending in `including messages under protected
labels`.

## Hosted VM services

The single connection can be run from a hosted instance rather than a laptop.
The private VM deployment keeps four boundaries separate: machine status,
the authenticated owner dashboard, the short-lived Gmail runner, and the
timer/path units that start that runner.

**The key-encrypting key lives in Cloud KMS.** `connection_tokens.py` wraps
each token under a fresh data key and wraps that key with a KEK.
`FileKeyProvider` keeps the KEK in a 0600 file next to the data, which is
honest about its own limit. `KmsKeyProvider` (`connection_kms.py`) keeps it in
Cloud KMS instead, so a stolen disk, snapshot or backup yields ciphertext and
nothing more, and every unwrap appears in Cloud Audit Logs. A compromise of the
*running* host still reaches the mailbox; that is inherent to a scheduler that
must open a sleeping person's mail, and it is stated rather than engineered
around.

The provider cannot create its own key. Provision it once, yourself:

```
gcloud kms keyrings create triage --location <LOCATION>
gcloud kms keys create connection-kek --location <LOCATION> \
    --keyring triage --purpose encryption
```

Grant the runtime service account `roles/cloudkms.cryptoKeyEncrypterDecrypter`
on that key alone.

**The machine status endpoint is read-only.** `hosted_status.py` serves
`GET /healthz` (no credential, liveness only) and `GET /` (bearer, JSON
status). No response carries the connected address — the opaque connection id
says whether a connection exists without saying whose — and the module imports
nothing that can reach a token, so a compromise there yields status, not mail.

The separate human dashboard on port 8081 remains bound to loopback. Its normal
sign-in is a single **Continue with Google** button that starts a PKCE-protected
OAuth flow. The login page does not show the operator recovery credential. A
successful Google callback establishes the dashboard session immediately, so
an owner does not copy a separate credential before linking or reconnecting Gmail. The
dashboard can save a complete label/schedule/draft approval bundle and
disconnect only after the owner types the connected address. Its OAuth callback
consumes ten-minute, single-use state before token exchange. A returned refresh
token exists only in memory until Cloud KMS encryption. Disconnect attempts
Google revocation, then destroys the local encrypted credential even when
revocation cannot be confirmed. Gunicorn access logging is disabled for this
service so callback authorization codes never enter the system journal.

The dashboard's **Scan new mail** and **Scan previous emails** actions do not
import Gmail code, decrypt a token, or launch a privileged command. They write
one private, account-bound request under `/mnt/state/active`.
`hosted-triage.path` notices that exact file and starts the same sandboxed
oneshot service used by the daily timer. The runner consumes the request before
mailbox access, refuses altered or hour-old requests, and bypasses the
schedule/same-day gate. New-mail scans use the recent overlap window; an
explicit history scan accepts 1–250 and searches the newest eligible messages
without an age cutoff. The selected batch size automatically reserves enough
label writes and drafts to finish every eligible message in that batch.
Reviewed settings, account identity checks, spam and unsafe-reply exclusions,
and per-message duplicate prevention still apply.

While an immediate run is starting or working, the dashboard refreshes its own
status briefly and reports completion or a safe failure reason. The runner
validates the Google refresh token before mailbox work; if Google rejects it,
the dashboard asks the owner to reconnect instead of leaving a run that merely
appears slow. Draft guidance is editable, and the default prompt favors warm,
specific, natural replies while preserving the no-invention and never-send
rules.

**The state volume must be a real filesystem, and must actually be mounted.**
The lifecycle rests on `os.replace` for every state write and `fcntl.flock` for
the run lease. A GCS-FUSE mount supports neither reliably, which is why the
target is a Compute Engine persistent disk formatted ext4: it provides both
natively.

The subtler trap is specific to a VM. An unmounted disk does *not* make the
path disappear — the mountpoint directory still exists on the boot disk, is
ext4, and passes every probe the process can make from inside itself. The
service would run, write a real connection record to the wrong disk, and lose
it the moment the intended disk was mounted over the top. Two independent
defences: `RequiresMountsFor=` in the systemd unit, which stops the service
before it starts, and `HOSTED_REQUIRE_MOUNTPOINT` (default true), which is the
application's own check. Verify a freshly mounted disk before trusting it:

```
python hosted_status.py --check-state-root /mnt/state --require-mountpoint
```

**It runs under systemd, not in a container.** On a single VM serving one
connection an image buys a registry, a pull credential on the instance and a
build step, for one Python process with one dependency. systemd gives what
matters here instead: `RequiresMountsFor`, and a sandbox in which
`ProtectSystem=strict` plus a single `ReadWritePaths` makes the state disk the
only writable path — so a compromise of the service cannot rewrite the
service.

**There is no public listener.** The unit binds gunicorn to `127.0.0.1`;
reach it over an SSH tunnel:

```
gcloud compute ssh <VM> -- -N \
  -L 8080:127.0.0.1:8080 \
  -L 8081:127.0.0.1:8081
```

The bearer and forwarded-https checks remain in the code regardless. The
binding is a deployment choice the module cannot verify, and defence that only
holds while a config file says so is not defence.

Installation or recovery order:

1. Provision the KMS key ring and key; grant the VM's service account
   `roles/cloudkms.cryptoKeyEncrypterDecrypter` on that key alone.
2. Create the VM and attach a persistent disk; format ext4, mount at
   `/mnt/state`, and add it to `/etc/fstab` so it survives a reboot.
3. Deploy the code, virtualenv, installed-app OAuth client,
   `/etc/email-scanner/hosted.env`, and the status, dashboard, runner, timer,
   and path units;
   verify the disk with `--check-state-root --require-mountpoint` before
   enabling a service.
4. Confirm `/healthz` answers through the tunnel, the status endpoint refuses
   without a bearer, and **Continue with Google** opens the OAuth flow.
5. Complete Google consent, save the reviewed labels and schedule, then use
   **Scan new mail** for recent messages or **Scan previous emails** for a
   bounded catch-up. The dashboard follows the run automatically and explains
   if Google must be reconnected.
   The command-line broker flow below
   remains a recovery option:

```
python broker_client.py mint-invite
# the owner visits https://<broker>/start/<invite> and consents
python broker_client.py collect --url https://<broker>/pickup/<invite> \
    --private broker-operator.key --token-out ./token.json

python connect_account.py --root /mnt/state --account <address> \
    --token ./token.json --yes
```

`connect_account.py` is the only place that calls Cloud KMS for real, and it
does so through an injected client factory whose default import of
`google.cloud.kms` lives inside the factory function - so importing the module
reaches nothing and its tests run offline against a double.

It needs two libraries on the host, `google-cloud-kms` and **`google-crc32c`**.
The second is not optional and not merely defensive: every KMS request carries
a CRC32C of its payload, and Cloud KMS reports `verified_plaintext_crc32c` as
false when a request arrives with no checksum to verify. A provider that sends
none therefore fails every call while reporting corruption that never happened.
The checksum function is injected like the client, and its default fails loudly
rather than skipping the checksum when the library is absent.

The address is asserted by the operator and cannot be checked here: the broker
seals only `refresh_token`, `scope` and `token_type`, having no business
retaining an address. If a token document ever does carry one it must agree,
and a mismatch is refused. Getting the address wrong leaks nothing - the token
still opens only the mailbox it was issued for - but it files the archive and
the occupancy record under the wrong identity, which is why `--yes` is
required. The only real verification is a read-only Gmail profile check, which
is a live call and a separate step.

On success the plaintext credential is deleted. On failure it is deliberately
kept, and the command says so: a failed store that also destroyed the
credential would cost the account owner another round of consent for nothing.

Steps 1, 2, 3 and 5 touch a real cloud account or mailbox. They are the
operator's to perform.

## Required rollout order

1. Run all offline tests and fake Gmail demonstrations.
2. Obtain institutional IT OAuth approval.
3. Authorize exactly `owner@example.edu` into `tokens/owner.json`.
4. Verify the authorized Gmail profile/account with a read-only check.
5. Preview owner-account label setup, then confirm exact label creation.
6. Run `--estimate-only` for the approximately two-month backfill.
7. Run a small interactive live dry run and inspect classifications.
8. Run the read-only `YEAR_LABEL` campaign audit.
9. Have the account owner review and explicitly approve the recipient allowlist.
10. Run a one-to-three-draft campaign pilot and inspect every result.
11. Test rollback only against the pilot's program-created draft log.
12. Review the account taxonomy, set `draft_all_replyable_messages` and the
    `Other` fallback, then have the owner create the one-time digest-bound
    activation. Grant protected-label drafting separately, if appropriate.
13. Run a small daily-triage draft-only pilot and inspect every label/draft,
    including an unknown message, an ordinary human reply, and a suppressed
    newsletter or bounce (which must receive no draft).
14. Enable the 6:00 PM `--scheduled --apply --yes` run only after explicit
    approval. Keep all three limits in the installed command.

Before real-account writes, also confirm exclusion sources, exact campaign
text, each enabled category's drafting approval, and the pilot size. Passing offline tests
makes this suitable for staged review; it does not make the system
production-ready or override institutional policy.

Official references: [Gmail OAuth scopes](https://developers.google.com/workspace/gmail/api/auth/scopes),
[Gmail label behavior](https://developers.google.com/workspace/gmail/api/guides/labels),
and [`users.labels.create`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/create).
