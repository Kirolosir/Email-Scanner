# Example Email Drafting Tool

This project supports three guarded workflows: campaign reply drafts from a
Gmail label, incoming-email triage with add-only labels and template replies,
and an idempotent once-daily inbox processor. It never sends mail
automatically. Production code contains no Gmail send operation, and an
offline regression test rejects one if it is introduced.

Both drafting workflows are approval-gated, and both default to creating
nothing. A campaign needs a reviewed recipient allowlist for the protected
`2027B` label. Triage needs a per-template approval recording that a human
read that template's exact wording — supplying real template text is not by
itself approval to draft with it. See
[Template approval is required even after a template is real](#template-approval-is-required-even-after-a-template-is-real).

Google documents `gmail.modify` as able to read, compose, **and send** email.
It is the least-privileged single scope supporting this tool's reads, draft
creation, label additions, and explicitly requested rollback-to-Trash. Gmail
does not offer a broad draft-creation scope that is technically incapable of
sending. Application structure, tests, previews, confirmation gates, and
logs—not OAuth—enforce the no-send boundary.

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

Google opens its own sign-in/consent page. This application never collects the
Gmail password. For a second account, keep a separate ignored token and verify
the exact account:

```sh
.venv/bin/python gmail_auth.py --authorize \
  --token-path tokens/coach.json \
  --expected-account "owner@example.edu"
```

The attempted coach authorization is currently blocked by Example's Workspace
policy with `Error 400: admin_policy_enforced`. That is an administrator
decision, not a software error. Do not change clients, accounts, or scopes to
work around it. No coach-account setup, scan, label, draft, or schedule
activation may occur until Example IT approves the OAuth application and exact
account authorization succeeds.

A hosted OAuth broker now exists in the repository so an account owner can
authorize from their own device. It is written and tested but **not deployed**
and has never been stood up; see
[Hosted OAuth broker](#hosted-oauth-broker-not-deployed). The desktop flow
above is unchanged and remains the only path used so far.

Secret files, tokens, logs, caches, state, and virtual environments are
ignored. On POSIX systems, token/state files use mode 0600 and their private
directories use 0700. Changing OAuth scopes requires deliberate
re-authorization; never do that during a campaign run.

## Offline checks

The demos use fake Gmail, synthetic messages/templates, and stub classifiers:

```sh
.venv/bin/python demo_triage_flow.py
.venv/bin/python demo_daily_triage.py
.venv/bin/python demo_classify_batch.py
.venv/bin/python -m pytest -q
```

No default demo uses the network. Gemini requires an explicit live path.
Imports and CLI `--help` paths are network-free and do not load `.env`.

## Urgent `2027B` campaign

`2027B` is the exact urgent campaign label. Campaign deduplication uses the
normalized sender email address; known aliases can be provided explicitly with
`aliases.example.txt`. There is no AI identity matching.

Start with a test account and dry run:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python campaign.py "2027B" body.txt \
  --aliases aliases.example.txt --exclude exclusions.example.txt \
  --limit 2 --dry-run
```

The supplied `body.txt` contains the coach-provided campaign wording and direct
registration links. Preserve it unless the coach approves an edit. A full scan
may cover roughly 9,000 messages and take approximately 30–40 minutes under the
current quota pacing. `--limit` limits drafts after deduplication; it does not
skip the scan required to select newest threads reliably.

Every created draft ID is flushed to `draft-logs/`. Preview and then roll back
only one recorded run with:

```sh
.venv/bin/python campaign.py --undo draft-logs/campaign-YYYYMMDD-HHMMSS.log --dry-run
.venv/bin/python campaign.py --undo draft-logs/campaign-YYYYMMDD-HHMMSS.log
```

Rollback moves the associated draft messages to Trash after its own
confirmation; it never permanently deletes them.

`2027B` is a protected campaign label. A dry run without an approval file is
allowed for inspection, but it prints `UNREVIEWED` and real draft writes remain
blocked. Before a real run, create a private read-only recipient audit. This
command reads Gmail and calls Gemini for normal unique recipients, but has no
Gmail write operation:

```sh
.venv/bin/python campaign_audit.py "2027B" \
  --token-path tokens/coach.json \
  --aliases aliases.example.txt \
  --output audit-reports/2027B-REVIEW.json
```

The audit report contains recipient addresses and therefore uses directory
mode 0700 and file mode 0600. It never stores subjects, bodies, credentials,
tokens, or free-form model reasoning. `candidate_for_human_approval` is a
recommendation, not approval. The coach must review the population and prepare
a separate approval file based on `campaign-approval.example.json`:

Use `--max-scan` and `--limit` for the first audit pilot. A full audit of roughly
2,000 unique recipients can require several hours at six seconds between model
calls, before Gmail latency or retries, and can consume paid/API quota.

```json
{
  "version": 1,
  "account": "owner@example.edu",
  "label": "2027B",
  "approved_recipients": ["reviewed-recruit@example.com"]
}
```

Keep the real file private and ignored, for example:

```sh
chmod 600 campaign-approval.coach.json
```

The campaign validates the approval against Gmail's actual authenticated
account and exact label, rejects malformed/empty/conflicting recipients, then
intersects it with aliases and exclusions. A small reviewed pilot is:

```sh
.venv/bin/python campaign.py "2027B" body.txt \
  --token-path tokens/coach.json \
  --approval campaign-approval.coach.json \
  --aliases aliases.example.txt --exclude exclusions.example.txt \
  --limit 3 --dry-run
```

Remove `--dry-run` only after the preview is correct. There is no bypass flag
for the protected-label approval gate.

## Classification and templates

The validated categories are:

- `recruit_intro`
- `recruit_update`
- `video_update`
- `parent`
- `other_coach`
- `camp_inquiry`
- `administrative`
- `other`
- `unknown`

Gemini returns category, graduation year, sender type, confidence, evidence,
and a short reason in a strict format. Unsupported/malformed output becomes
`unknown`; raw model output and message bodies are never logged. Automatic,
bulk, bounce, no-reply, malformed, and unsafe Reply-To messages are stopped
before Gemini and never drafted. Classification sends the safe reply metadata,
subject, and at most 8,000 characters of the cleaned current top-posted message
to Gemini. Quoted history, common signatures, and attachment contents are not
included. Gmail approval alone is insufficient; retain Example's approval for
that data processing before enabling it.

Templates resolve in this order:

1. `templates/<category>_<grad_year>.txt`
2. `templates/<category>.txt`

A `[PLACEHOLDER TEMPLATE ...]` marker always blocks real drafting. The current
category templates, including `video_update`, `other_coach`, `administrative`,
and `other`, remain placeholders until The Account Owner supplies exact approved
wording. Unknown, ambiguous, conflicting, malformed, or missing-template cases
receive `Needs Review` and no generated reply.

### Template approval is required even after a template is real

Replacing a placeholder with real wording does **not** start drafting.
Removing the placeholder marker only clears the first of two independent
gates. A template is used for draft creation only when it is both:

1. not `[PLACEHOLDER TEMPLATE ...]` marked, and
2. explicitly approved for its exact template key.

The default is fail-closed: with no approval supplied, triage still classifies
and applies labels normally, and skips only draft creation, logging
`template unapproved: no reviewed approval for '<key>'`. That appears in the
same place as missing-template and `other` skips, and those messages route to
`Needs Review` as usual.

Approval is per template key, never global. Approving `recruit_intro` does not
activate `parent` or `camp_inquiry`. Because `recruit_intro_2027.txt` is
different wording from `recruit_intro.txt`, it is also approved separately.
Approval can never unlock a placeholder: the marker is checked first.

Both `triage.py` and `daily_triage.py` accept the two flags below, and both
share one enforcement point, so the scheduled 6 PM run is gated identically.

**`--template-approval FILE` (wording-bound; use this for real runs).** The
artifact pins each approved key to the SHA-256 digest of the exact reviewed
text, so editing a template after approval automatically revokes it rather
than carrying the approval over to wording nobody has read:

```sh
.venv/bin/python triage.py "INBOX" \
  --template-approval template-approval.coach.json --limit 5 --dry-run
```

**`--templates-approved KEYS` (name-only; supervised runs only).** A
comma-separated list of keys approved for one run. It is deliberately weaker:
it does **not** pin wording, so it attests only that an operator named the key
on the command line. Use it for interactive pilots where a human inspects each
draft, never for scheduled runs:

```sh
.venv/bin/python triage.py "INBOX" \
  --templates-approved recruit_intro,parent --limit 5 --dry-run
```

Both commands print the active approvals, and the name-only form prints an
explicit warning that wording is not pinned.

To build an approval artifact, generate the digest of each reviewed template.
This command reads one local file and makes no network call:

```sh
.venv/bin/python -c "from triage import template_digest; print(template_digest(open('templates/recruit_intro.txt', encoding='utf-8').read()))"
```

Copy each digest into a private file based on `template-approval.example.json`,
listing only templates a human has actually read:

```json
{
  "version": 1,
  "account": "owner@example.edu",
  "label": "2027B",
  "approved_templates": {
    "recruit_intro": "sha256:dc25272e...66218"
  }
}
```

`account` is required and is checked against the authenticated Gmail account,
the same way the campaign approval artifact is bound. An approval reviewed on
the test account therefore cannot authorize drafting in the coach's mailbox;
the run fails with `template approval account does not match the
authenticated Gmail account`. Address comparison is normalized, so
`Coach <coach@example.edu>` and `COACH@EXAMPLE.EDU` match.

`label` is optional, because the daily processor scans an inbox query rather
than a single label. Omit it and the artifact applies to any label within its
account. Include it and it is honored strictly: it must equal the label passed
to `triage.py`, and a run that does not target one label — the daily
processor — is refused outright rather than silently widened. For a
`daily_triage.py` artifact, leave `label` out.

Structure is validated before any Gmail contact, so a malformed file fails
immediately; the account binding is then enforced after authorization, once
the authenticated account is known.

Keep the real file private and ignored; `template-approval*.json` is already
ignored apart from the example:

```sh
chmod 600 template-approval.coach.json
```

Malformed artifacts are rejected rather than partially applied: a wrong
version, an empty `approved_templates`, a non-string key, or a digest that is
not `sha256:<64 hex>` all fail the run instead of silently leaving a template
unapproved-but-assumed-approved.

One limit this gate does not cover: the digest proves the wording is unchanged
since the artifact was written, and the account binding proves it was reviewed
for this mailbox, but neither can prove a human actually read the text. That
remains an operator responsibility, as it does for the campaign allowlist.

## Exact label policy and bootstrap

`2027B` is reserved for email sent by an actual 2027 recruit in a recruiting
category. The model's year is never sufficient. The cleaned current message
must also contain deterministic recruiting-year evidence such as `Class of
2027`, the classifier must be high confidence, and the local/model years must
agree. Dates, schedules, phone numbers, quoted history, and footers do not
qualify. Parent, other-coach, administrative, automated, vendor, and reporter
messages do not receive it merely because their text mentions a 2027 recruit.
Low/medium confidence and contradictory evidence route to Needs Review with no
draft.

`label-config.example.json` contains the reviewed mapping:

- existing-only year label: `2027B`
- category labels under `Example/Triage/...`
- `Example/Triage/Needs Review`
- hidden `Example/Triage/Processed`

The legacy `triage.py` and daily processor never create labels. The separate
bootstrap command is the only module allowed to create the exact configured
triage labels. Preview it on a test account:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python setup_labels.py \
  --config label-config.example.json --dry-run
```

After reviewing the exact list:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python setup_labels.py \
  --config label-config.example.json
```

Setup is idempotent, requires typed confirmation, never creates `2027B`, never
accepts a free-text label name, never consumes classifier output, and never
renames/removes/deletes a label.

## Two-month backfill and daily triage

Before classification, estimate the initial workload using metadata only. This
makes zero Gemini calls and zero Gmail writes:

```sh
.venv/bin/python daily_triage.py initial \
  --token-path tokens/coach.json --estimate-only --scheduled
```

The estimate counts already-processed, automated, invalid-metadata, and Gemini
candidate messages, and reports minimum model-spacing time using the configured
six-second interval. Actual time may be longer because of Gmail latency and
retries.

`daily_triage.py` defaults to dry run. Initial mode searches only Inbox mail
from approximately two months and explicitly excludes Spam, Trash, Sent, and
Drafts:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py initial \
  --config label-config.example.json --max-scan 50 --limit 10 --dry-run
```

After a reviewed test-account preview, approved templates, and a small pilot,
the explicit write gate is:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py initial \
  --config label-config.example.json --template-approval template-approval.coach.json \
  --max-scan 50 --limit 10 --apply
```

`--apply` authorizes Gmail writes; it does not approve any template. Without
`--template-approval` (or, for a supervised run, `--templates-approved`), the
run above still labels normally and creates zero drafts, reporting each
skipped category as `template unapproved`. That is expected, not a failure.

Daily mode searches a three-day overlap to avoid missed late-arriving mail:

```sh
GMAIL_TOKEN_PATH=token.json .venv/bin/python daily_triage.py daily --dry-run
```

Important terminology:

- A live `--dry-run` prevents Gmail writes, but still reads Gmail and may call
  Gemini.
- `--estimate-only` reads Gmail metadata, makes zero Gemini calls, and makes
  zero Gmail writes.
- The offline demos/tests use fake Gmail and stub classifiers and make zero
  network calls.

It skips messages already carrying `Example/Triage/Processed` or marked
complete in its private journal. The atomically written journal lives under
`triage-state/`, uses owner-only permissions, and stores IDs/statuses—not
subjects, senders, bodies, credentials, or model output. Existing draft threads
are reconciled before creation. A manual/external thread draft is never adopted,
modified, or entered into a rollback log; it is routed to Needs Review. A draft
provably created by this program can be recovered from its journal. If
interrupted after draft creation but before the processed label, the immediately
flushed draft log and journal prevent a duplicate on restart.
Corrupt/unsupported authoritative state blocks rather than resetting.

Every run also takes a crash-safe, nonblocking OS lock keyed by a private hash
of its target. A concurrent same-target run exits with status 75 before Gmail
contact. A PII-free atomic status file records the last attempt/success, counts,
safe error codes, and lock conflicts. Runtime/state/status directories are 0700
and private files are 0600.

Each message is isolated: one API/classification failure does not discard the
other plans. Labels are add-only. Drafts are replies in existing threads and
remain unsent for individual review.

## Prepared 6 PM macOS schedule (not installed)

`launchd/com.example.email.daily-triage.plist.example` is prepared for 6:00 PM
local time with absolute paths and no secrets. It includes `--apply --yes`, so
do not install it until every rollout gate below passes. The computer must be
running and online; the same-day guard and processed journal make duplicate
invocations harmless. Its non-secret `--token-path` points specifically to
`tokens/coach.json` so a scheduled coach run cannot silently use `token.json`.
The Mac's system timezone must remain America/New_York for 18:00 to mean the
requested Eastern-time run.

The plist also uses `--scheduled`. Unattended output contains counts, label
category names, opaque identifiers, timestamps, and safe error codes only; it
does not contain subjects, addresses, bodies, classifier reasoning, or secrets.

Before eventual activation, create private scheduler logs:

```sh
mkdir -p automation-logs
chmod 700 automation-logs
touch automation-logs/daily-triage.out.log automation-logs/daily-triage.err.log
chmod 600 automation-logs/*.log
```

Copy the reviewed plist to `~/Library/LaunchAgents/`, validate with
`plutil -lint`, and enable with `launchctl bootstrap gui/$(id -u) ...`.
Inspect with `launchctl print gui/$(id -u)/com.example.email.daily-triage`.
Pause/remove with `launchctl bootout gui/$(id -u) ...`. These are future
operator instructions only; the project does not install or activate the job.

## Hosted OAuth broker (not deployed)

`oauth_broker.py`, `broker_crypto.py`, `broker_client.py`, and `broker_wsgi.py`
let an account owner complete Google sign-in on their own device, without the
operator's machine being involved. Nothing here has been deployed, no hosting
account has been provisioned, and no public URL exists.

The credential passes through Google and the broker only. The broker seals the
refresh token to a public key the operator generated locally, so it can encrypt
but never decrypt: a fully compromised broker yields ciphertext, not a Gmail
token.

### Single instance is a correctness requirement

The pending-state, invite, and pickup stores live in the web worker's memory.
A second instance would not see states minted by the first, sign-ins would fail
intermittently, and the single-use guarantees would hold only per instance.
`render.yaml` pins `numInstances: 1` and `--workers 1`, and a test asserts both.
Moving to more than one process means moving those stores to shared storage
with identical single-use semantics first.

Threads are fine: `MemoryStore.take` removes with a single `dict.pop`, so two
concurrent callbacks cannot both consume the same state.

### On the free plan the real window is one sitting, not 24 hours

The deployed broker (`srv-dabdm24s728c73adbr70`, "Email Scanner") runs on
Render's **free** plan. Confirmed on the dashboard: Manual Scaling is 1,
autoscaling is off, and free instances cannot scale at all — so the
single-instance requirement above is enforced by the plan itself, not merely
by configuration.

The same plan carries a consequence that matters more. **Free instances spin
down after periods of inactivity, and a spin-down wipes everything held in
memory.** The invite, pending-state, and pickup stores are all in the web
worker's memory, so:

| Store | Survives a spin-down? | Consequence |
| --- | --- | --- |
| Seeded invites | Yes | Re-seeded from `BROKER_INVITE_IDS` at boot |
| Pending OAuth states | **No** | An owner who takes longer than the idle window between opening the link and finishing Google sign-in gets "this link is not valid or has already been used" |
| Sealed pickups | **No** | A credential the operator has not collected yet is **destroyed**, and `/pickup` then returns 404 exactly as though it had already been collected |

So on the free plan, treat the whole flow as **one continuous sitting**: mint
the invite, have the owner sign in, and collect the credential without a long
idle gap. The failure mode is quiet and misleading — both losses look
identical to "already used", which is the same response a genuine replay gets.

To get an actual 24-hour window, either move to a paid instance (no spin-down)
or persist the pickup store. Persisting it is not a free choice: it puts
sealed credentials somewhere other than one process's memory, and that
tradeoff should be reasoned through before it is built, not assumed.

### Target

Render is the recommended host: it builds a Python service from
`broker-requirements.txt` with no Dockerfile, and one instance is the default
rather than something to remember to configure. Fly.io works equally well, but
`fly launch` can create two machines by default, which is exactly the failure
above — if you use Fly, set `min_machines_running = 1`, disable autoscaling,
and confirm only one machine exists before sending anyone an invite.

`Procfile` carries the same start command for any Procfile-style host.

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

It prints the public half. Put that in `BROKER_OPERATOR_PUBLIC_KEY`. Keep
`broker-operator.key` (mode 0600) — without it the sealed credential is
unrecoverable, and there is no way to ask the broker for a second copy.

Generate the pickup credential too:

```sh
.venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 2. Mint an invite

Invites are created offline and seeded through configuration. Nothing
reachable over the network can create one, so there is no admin endpoint to
defend. A shell on the host would not work either — the stores live in the web
worker's memory, and a shell is a different process.

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

Single use. The invite id itself is re-seeded from configuration at every
boot, but the sign-in it starts is not: on the free plan the owner should
open the link and finish while you are still with them, because an idle
spin-down loses the pending state. The owner opens it, signs in with Google, and
sees a plain confirmation page. That page contains no token and no code, and
says explicitly that nothing was sent from their account and no message was
read during sign-in.

If they abandon it, or the state's 10-minute window lapses, mint a fresh
invite. Nothing is reusable by design.

### 4. Retrieve the sealed credential

```sh
export BROKER_OPERATOR_BEARER='<the value you generated in step 1>'

.venv/bin/python broker_client.py collect \
  --url https://your-broker-host.example.com/pickup/<invite-id> \
  --private broker-operator.key \
  --token-out tokens/coach.json
```

The bearer is read from the environment, never from the command line, because
arguments are visible to every process via `ps`.

Pickup is one time: a successful fetch deletes the ciphertext. A *failed*
authorization does not consume it, so a wrong bearer cannot destroy the
credential. `collect` refuses to overwrite an existing token file.

After that, `tokens/coach.json` is an ordinary credential and the existing
`--token-path` flags use it unchanged.

### Before standing any of this up

- The Google OAuth client must be type **Web application**, with the exact
  `BROKER_REDIRECT_URI` registered. The desktop client used by `gmail_auth.py`
  will not work here.
- Example's `admin_policy_enforced` block applies to the broker exactly as it
  does to the desktop flow. The broker does not work around an administrator
  decision and must not be used to try.
- There is no rate limiting in the app; put it in front.
- TLS termination is the host's job. The app enforces `https`, honouring
  `X-Forwarded-Proto` so a hosting proxy does not cause it to reject every
  request.
- Sealed ciphertext is held **in memory only**. On the free plan an idle
  spin-down destroys it, so collect it in the same sitting rather than
  relying on a 24-hour window — there is not one. See
  [On the free plan the real window is one sitting](#on-the-free-plan-the-real-window-is-one-sitting-not-24-hours).

## Required rollout order

1. Run all offline tests and fake Gmail demonstrations.
2. Obtain Example IT OAuth approval.
3. Authorize exactly `owner@example.edu` into `tokens/coach.json`.
4. Verify the authorized Gmail profile/account with a read-only check.
5. Preview coach-account label setup, then confirm exact label creation.
6. Run `--estimate-only` for the approximately two-month backfill.
7. Run a small interactive live dry run and inspect classifications.
8. Run the read-only `2027B` campaign audit.
9. Have the coach review and explicitly approve the recipient allowlist.
10. Run a one-to-three-draft campaign pilot and inspect every result.
11. Test rollback only against the pilot's program-created draft log.
12. Supply the eight real category templates, then review each one's exact
    wording and record its digest in a private `--template-approval` artifact.
    Replacing a placeholder is not approval; drafting stays blocked per
    category until its key is approved.
13. Run a small daily-triage draft-only pilot and inspect every label/draft.
14. Enable the 6:00 PM schedule only after explicit approval.

Before real-account writes, also confirm exclusion sources, exact campaign
text, all category/year templates, and the pilot size. Passing offline tests
makes this suitable for staged review; it does not make the system
production-ready or override Example policy.

Official references: [Gmail OAuth scopes](https://developers.google.com/workspace/gmail/api/auth/scopes),
[Gmail label behavior](https://developers.google.com/workspace/gmail/api/guides/labels),
and [`users.labels.create`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/create).
