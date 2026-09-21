# Architecture and Operations

This guide covers the parts of Email Scanner that are useful when reviewing,
running, or deploying the project. The shorter product overview is in
[README.md](README.md).

## Architecture

The application is split into narrow components:

- `hosted_dashboard.py` serves the owner dashboard and settings pages.
- `oauth_broker.py` completes Google OAuth without exposing client secrets to
  the browser.
- `hosted_runner.py` checks the schedule, opens the encrypted credential in
  memory, and starts a bounded triage run.
- `daily_triage.py` reads Gmail messages, classifies them, applies labels, and
  creates unsent reply drafts.
- `connection_tokens.py` and `connection_kms.py` provide envelope encryption
  backed by Cloud KMS.
- `retry_queue.py` persists bounded retry work without message content.
- `encrypted_backup.py` creates rotating backups and verifies each one.
- `private_runtime.py` owns atomic status files, locking, and safe diagnostics.

The public proxy terminates HTTPS and forwards to services bound to loopback.
The status service is read-only. The dashboard owns account controls, while
only the runner imports Gmail and credential code.

## Safety boundaries

The application creates drafts but never sends email. A static test rejects
Gmail send operations in production modules. Labels are add-only, and drafts
remain editable in Gmail until the account owner acts on them.

Other important boundaries:

- One Gmail account may be connected at a time.
- Connecting another account requires an explicit disconnect first.
- OAuth refresh credentials are encrypted at rest and decrypted only in the
  short-lived runner process.
- Dashboard sessions, OAuth state, approvals, and settings are validated
  independently.
- Scheduled work has scan, write, and draft limits.
- Existing manual drafts are preserved.
- Program-created drafts are journaled for idempotent restarts.
- Message bodies, subjects, addresses, and raw provider errors are excluded
  from dashboard status and service logs.
- Spam, trash, sent messages, self-replies, bounces, and unsafe reply metadata
  do not produce drafts.

The Gmail scope permits mailbox modification because labels and drafts require
it. The no-send guarantee is enforced in code and tests, not by a narrower
Google scope.

## Processing flow

1. The runner verifies the durable state volume and single-account record.
2. It checks an immediate request, the daily schedule, and the retry queue.
3. Cloud KMS unwraps the data key for the stored OAuth credential.
4. Gmail confirms the authenticated account before mailbox changes.
5. The pipeline loads reviewed labels and drafting settings.
6. Messages are fetched within the configured limit and grouped by thread.
7. Each message receives a category decision and matching Gmail labels.
8. Every safely replyable message receives one unsent draft for its thread.
9. Completion state, coverage, usage, and safe errors are written atomically.
10. Failed items enter the retry queue, then configuration and bounded run
    history are encrypted and backed up.

History scans accept 1 to 5,000 messages. Selections above 100 use up to three
concurrent batch jobs in 200-message groups. A durable background job completes
up to 1,000 messages per pass, releases the account between passes, and resumes
on the one-minute worker so recent-mail requests keep priority. Smaller
selections analyze up to four messages concurrently. Gmail writes use four
quota-paced workers, and message reads use the same bounded pool. Writes are
serialized per conversation thread. Category and
completion labels share one Gmail update after a draft is safely recorded.
Undo journals retain every change in the run without an item-count cutoff.
Retryable failures are deferred while later groups continue. The one-minute
timer checks for due retries without contacting Gmail when the queue is empty.

## Local setup

Python 3.11 or newer is recommended.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Create a Google OAuth client, enable the Gmail API, and place the downloaded
client document at the path configured by `GMAIL_CREDENTIALS_PATH`. Store the
Gemini key in `.env` for local work or in the deployment environment file.
Never commit either secret.

Run the offline test suite:

```sh
.venv/bin/python -m pytest -q
```

Useful read-only checks:

```sh
.venv/bin/python check_readiness.py --help
.venv/bin/python check_gmail_read.py --help
.venv/bin/python check_gemini.py --help
```

Commands that contact Gmail or modify labels and drafts require explicit
arguments and approvals. Use each command's `--help` output for current options.

## Account configuration

`account-config.generated.example.json` shows the configuration shape. The
dashboard writes an account-bound copy to the private state directory. Main
settings include the address, timezone, schedule, limits, labels, signature,
drafting guidance, and drafting modes.

Approval artifacts are digest-bound to the reviewed configuration. Changing
relevant settings invalidates the old approval instead of silently widening it.

## Hosted deployment

### Multi-account storage rollout

The first migration slice adds PostgreSQL ownership, session, mailbox,
credential, settings, job, message-state, rollback, and audit tables. It does
not switch the live dashboard away from the existing single-account files yet;
that cutover happens only after the user-specific OAuth and route checks are
complete.

Provision PostgreSQL 15 or newer. Set `DATABASE_URL` through the root-owned
deployment environment, install the dependencies, and apply the schema before
enabling the multi-account code:

```sh
.venv/bin/python db_migrate.py
```

Migration checksums are recorded in `schema_migrations`. Editing an applied
migration is refused; schema changes must be added as a new numbered file.
`HOSTED_MULTITENANT` remains false during migration. Enabling it switches the
dashboard to user-specific sessions and PostgreSQL mailbox ownership; it must
only be enabled after the existing account has been imported and the tenant
worker is installed.

The existing owner must sign in once through the new website flow before the
legacy account can be matched to a stable user identity. Then import it with:

```sh
.venv/bin/python legacy_tenant_import.py
```

The import re-encrypts the credential for its mailbox UUID, copies only the
reviewed runtime artifacts, and leaves the legacy connection untouched. A
mailbox stays out of the scheduler until the import reaches `ready`.

The tenant scheduler queues due mailboxes once per minute. Run multiple worker
instances so separate mailboxes progress concurrently while the database keeps
each individual mailbox single-operation:

```sh
systemctl enable --now tenant-scheduler.timer
systemctl enable --now tenant-worker@1 tenant-worker@2
systemctl enable --now tenant-worker@3 tenant-worker@4
```

These files document the VM layout:

- `Caddyfile.example`
- `hosted-dashboard.service.example`
- `hosted-status.service.example`
- `hosted-triage.service.example`
- `hosted-triage.timer.example`
- `hosted-triage.path.example`
- `hosted.env.example`

The production checkout is expected at `/opt/email-scanner`. Durable private
state is mounted at `/mnt/state`. Root-owned environment files under
`/etc/email-scanner` hold secrets and are not included in backups.

Required values are documented in `hosted.env.example`: the state root, OAuth
client path, Cloud KMS key, dashboard secret, public origin, and callback
configuration. The Gemini key is loaded only by the triage service.

Install the example unit files without `.example`, reload systemd, and enable
the dashboard, status service, timer, request path, and Caddy. The units run
unprivileged with a read-only system view and write access limited to state.

Operational checks:

```sh
systemctl is-active hosted-dashboard.service
systemctl is-active hosted-status.service
systemctl is-active hosted-triage.timer
systemctl is-active hosted-triage.path
systemctl is-active caddy
```

The login route should answer over HTTPS. `/healthz` on the protected dashboard
may redirect to login; the loopback status service provides machine health.

## Reliability and recovery

The dashboard reports processing totals, draft coverage, retrieval failures,
fallbacks, queued retries, Gmail requests and quota, model calls and tokens,
estimated cost, run time, and backup health. Token prices are configurable with
`GEMINI_INPUT_USD_PER_MILLION_TOKENS` and
`GEMINI_OUTPUT_USD_PER_MILLION_TOKENS`.

Backups contain configuration, approvals, the idempotency journal, status,
retry state, and bounded review and draft logs. Each archive uses a fresh data
key wrapped by Cloud KMS. Restore code refuses a non-empty destination and
unsafe paths. `test_reliability_runtime.py` covers encryption, verification,
and a full offline restore.

Each hosted apply run also writes a private rollback journal immediately after
every successful label or draft change. The dashboard can queue an undo only
for the latest recorded run and only after typed confirmation. The runner moves
that run's new drafts to Trash, removes only its recorded label additions, and
clears the matching completion records so the messages can be scanned again.
Rollback progress is saved after each change, making retries idempotent.

## Release checks

The suite covers OAuth, credential encryption, KMS integrity, single-account
enforcement, no-send behavior, label safety, prompt injection, draft
idempotency, retries, backups, authentication, service sandboxing, and
deployment configuration.

```sh
git diff --check
.venv/bin/python -m pytest -q
```

Deploy only a committed revision, run focused tests on the VM, restart the
dashboard and status services, and confirm the deployed hash. A deployment
should not manually start a mailbox scan.
