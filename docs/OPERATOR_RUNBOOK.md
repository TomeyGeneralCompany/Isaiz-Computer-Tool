# AutoHack operating and verification guide (October 18, 2026)

## Current boundaries

CI exercises explicit scope denial, a real local source read via a mocked Ollama
tool conversation, deterministic replay on an owned vulnerable fixture, report
generation, the actual HackerOne request serializer intercepted in memory,
rejection behavior, duplicate prevention, and persistent submission recovery.
It sends **no** synthetic reports to real programs and makes **no** external
target requests. CI also starts, stops and restarts the real orchestrator and HTTP dashboard
against an isolated SQLite database, with all discovery and hunts disabled.
CI does NOT demonstrate live end-to-end autonomous hunting.

The launcher now keeps the Node orchestrator as its supervised PID. The
dashboard streams logs without an output-buffer ceiling and owns a separate
process group. Normal SIGTERM stops the dashboard group; unexpected dashboard
exit fails the orchestrator so systemd can restart it. Worker shutdown and
replacement also remove descendant processes, with one shared eight-second
shutdown deadline. The restart smoke signals only the launcher PID, so it
cannot conceal an orphan by killing the test's entire process group.

The native Ollama agent remains read-only. It may clone up to two explicitly
eligible public SOURCE_CODE repositories into its private workspace.
The separate scoped HTTP observer library only allows GET/HEAD with exact
scope, rate limit, total request budget, public IPv4 DNS pin, and disabled
redirect following. This observer is not yet exposed as a local Ollama tool.

## Setup / operations

1. On the CPU-only Linux host, use Node.js 22, npm, Python 3, Git and flock (util-linux).
2. Store platform keys and model settings in a local .env (0600); never commit secrets.
3. First installation or update: bash setup-and-run.sh --verify-only
   This installs the exact lockfile under Node 22, initializes the schema, runs
   local/model checks and a read-only provider check, and exits without starting
   hunts. Inspect data/host-acceptance.json if a check fails.
   For foreground operation after verification: bash run-complete-autohack.sh
4. Open dashboard on http://127.0.0.1:3456 (loopback only).
5. Verify the host and read-only provider access: bash scripts/verify-host.sh
   This saves private evidence in data/host-acceptance.json and returns nonzero
   for any failed check. It never submits a report. Stop a running AutoHack
   instance before changing dependencies. The isolated restart smoke now uses
   its own free loopback port; it does not stop a different dashboard on 3456.
   It tests the configured model with a fresh file marker and runs an owned
   fixture through the actual model, deterministic replay, report assembly,
   evidence review and an intercepted submission. Real-program proof still
   requires a genuine authorized finding.
6. Confirm the actual SQLite native addon builds: npm ci (not --ignore-scripts).
7. After all acceptance checks pass, you can install a supervised per-user
   systemd service with: bash scripts/install-user-service.sh
   Reinstalling explicitly restarts the service so the process uses this checkout,
   including when an older checkout was already running. This interrupts active work.
8. Explicit stop/start/restart/status: bash scripts/control-user-service.sh stop
   (or start, restart, status). Check logs with:
   bash scripts/control-user-service.sh logs
   This service restarts after a crash. It cannot execute while the computer
   is physically powered off or sleeping. To keep it running after logging out,
   you may need to explicitly enable user lingering under your Linux policy.
   Never run a second manually launched instance concurrently with systemd.

Start or pause new hunts by changing SECURITY_AUTO_HUNT_ENABLED in the dashboard.
Pausing stops *new* dispatches after an interruptible idle wait, not an
already-running hunt. Use the separate force-stop control to cancel an active
solver. SECURITY_MAX_DAILY_HUNTS caps dispatches across restarts by UTC day in
data/hunt-daily-quota.json. Failed starts also consume a slot. If a .lock file
persists after a crash, inspect the owning process; locks intentionally fail
closed rather than risk parallel dispatches.

Programs with ambiguous or missing explicit eligible URL scopes are skipped.
Findings outside the exact approved target URL (or the approved source-repo
subtree) are discarded before submission.

## Verified revenue and the $4,000 planning floor

SECURITY_MONTHLY_EARNINGS_TARGET_CENTS defaults to 400000. It can be changed
through the dashboard config overrides. This is a tracking target, not income
a system can guarantee. Only actual USD provider payments reconciled by the
operator go in data/verified-payouts.json, attributed to the UTC paidAt month.
Pending reports and awards are not payments.

After independently checking a receipt from a genuine paid bounty:

    npx tsx scripts/record-verified-payout.ts \
      --finding-id sf-REAL --provider hackerone \
      --transaction REAL_PAYMENT_ID --cents 15000 \
      --paid-at 2026-10-18T10:00:00.000Z \
      --evidence REAL_RECEIPT_REFERENCE

Those identifiers are illustrative only: use actual provider/bank records.
The CLI requires an existing rewarded finding linked to the same provider,
and the ledger is idempotent by provider transaction reference.

## Submission safety and recovery

data/submission-outbox.json records started, confirmed or uncertain states.
If HTTP fails after a request may have been dispatched, the outbox marks
uncertain and refuses automatic retry. First check the provider for an existing
report. Never clear an outbox record simply to force a duplicate submission.
Back up the file before any manual reconciliation.

## Regression suite

    npm ci
    python3 scripts/acceptance.py --offline

Use Node 22 for the locked native SQLite dependency. The offline profile runs
the Python regressions, typechecks, all ten TypeScript fixtures, native
SQLite/Drizzle/dashboard integration and launcher restart smoke. Its temporary
database is separate from the operator database. It emits
`production_verified: false`; passing proves these regressions only.

CI has both a static job using --ignore-scripts and a native integration job
using npm ci. The native job exercises actual SQLite and dashboard startup.
Neither job establishes actual local Ollama or provider operation. The full
host acceptance command remains:

    bash scripts/verify-host.sh

## Deployment repairs verified in development

- The setup and launch scripts select Node 22, matching the native SQLite ABI.
  The systemd unit retains that executable and PATH instead of selecting a
  potentially different nvm default after reboot. Setup rebuilds an incompatible
  SQLite addon and protects .env with mode 0600.
- Kernel-held locks prevent a second complete supervisor or local orchestrator
  in the same checkout. The smoke test verifies duplicate launch rejection and
  release of the lock across shutdown/restart.
- Model and endpoint settings use the same dotenv parser as the application.
  Environment values take precedence; the launcher does not replace a model
  configured in .env with its default before dotenv runs.
- Source acquisition and review share a validated repository-root selector.
  Report prose never supplies clone commands. Git receives argv, disables hooks,
  credential helpers, redirects and inherited Git configuration, and times out.
- Provider preflight sends one bounded authenticated GET, reports actionable
  401/403/429 errors, and never emits tokens or provider response bodies.
  Existing HackerOne requests now have 30-second deadlines and reject redirects.

## Dependency maintenance

The lockfile was regenerated with patched Next.js and transitive dependencies.
Drizzle ORM/Kit and node-cron were updated. Root overrides require patched
PostCSS and esbuild, including nested copies. A clean Node 22 `npm ci` and all
17 offline acceptance groups passed; lockfile and installed-package audits
reported zero known vulnerabilities on October 18, 2026. The production
dashboard build also passed against an isolated fixture database.
Setup runs `npm ci` on updates as well as first install,
so an existing node_modules directory cannot silently retain the previous lock.

## Outstanding host/provider-level acceptance gates

- End-to-end source acquisition and local Ollama on the actual CPU host.
- Evidence-producing reproducible security verification for real in-scope code.
- Real scoped HTTP request testing against an authorized lab, with policy limits.
- Provider credential setup, authenticated discovery and authorized submission
  demonstration; no synthetic submissions to any real program.
- Real verified payout reconciliation, and dashboard access controls if the
  UI is ever exposed outside localhost.

Do not call full unattended bounty production readiness achieved until these
gates have actually passed. The standalone offline fixture is not that proof.

## Repairs after the first actual laptop check

The initial clone lacked the configured database parent directory. Drizzle's
CLI printed the error but returned zero. The config now creates that directory,
and setup checks the actual tables before proceeding. A regression covers both
fresh nested directories and a fake zero-exit initialization failure.

Restart smoke uses an ephemeral loopback port and retains isolated runtime
state. It does not commandeer an existing dashboard's listener.

Host model fixtures now have a six-turn, 128-token-per-response limit with a
2048-token context and four CPU threads. Their default budget is ten minutes;
`LOCAL_AGENT_TEST_TIMEOUT_MS` can override it from 1000 to 1800000 ms. Timing
logs identify the last requested/completed turn. These changes are regression
tested with intercepted model responses; they do not establish that the real
CPU/model timeouts have been resolved. Rerun the actual host acceptance.

For a rejected HackerOne credential pair, run
`bash scripts/configure-hackerone.sh` locally. It prompts for the username and a
hidden API token, checks authenticated read access, then atomically saves .env
with mode 0600 only if the check succeeds. Rejected credentials are not saved.
Never paste the API token into chat.

## Qwen tool-protocol compatibility

The actual laptop produced free-form intention/reasoning text instead of tool
calls. The default native Ollama runner now uses `LOCAL_OLLAMA_TOOL_PROTOCOL=json`:
a strict JSON schema selects one allowed read-only action, the runner executes
it through the same workspace path checks, and the real filesystem result is
returned to the model. The native API tools adapter remains available with
`LOCAL_OLLAMA_TOOL_PROTOCOL=native`. JSON mode omits the API `tools` field to
avoid its model-template rendering path. Neither mode executes model prose.

A final answer is rejected until at least one file was read successfully;
fixtures additionally require the correct fresh random marker or source read.
Truncated JSON gets a bounded generation-budget increase, not a fabricated tool
call or answer. Regression tests cover both protocols, forbidden paths, final
answers without successful reads, malformed actions and timeouts.

After infrastructure/account checks have passed, rerun only the outstanding
model checks with `bash scripts/verify-model.sh`. This writes private evidence
to data/model-acceptance.json. It never marks production verified or submits a
real report. Full acceptance remains available through scripts/verify-host.sh.

### Actual CPU model verification of the JSON protocol

On October 18, 2026, Ollama 0.40.6 running CPU-only with the actual downloaded
qwen3:4b model passed both the fresh-random-marker file-read fixture and the
model -> owned source read -> deterministic replay -> evidence -> report ->
review -> intercepted submission fixture. No real bounty report was submitted.
This verifies the protocol against a real model in development; the operator's
Ollama version and laptop still need the same narrowed model check.

References: Ollama structured outputs documentation
(https://docs.ollama.com/capabilities/structured-outputs) and the upstream Qwen
native-tool prompt report (https://github.com/ollama/ollama/issues/14601).

A repeated real-model run exposed a one-character marker transcription error.
The runner now accepts an optional final-answer validator; failed validation
returns corrective feedback within the same bounded turn budget. The marker
validator does not reveal the expected value or replace the model's answer.
The original 24-character fresh marker comparison and successful-read checks
remain unchanged. After this repair, the exact model-only command passed with
real CPU Qwen3:4b, including the replay/report fixture, followed by two additional
fresh-marker runs. A mock regression verifies rejected-final -> reread -> valid
final recovery. These are owned-fixture checks, not real-program bounty proof.


## Program assessment JSON recovery

Program ranking uses a separate text adapter from the source-reading agent.
The local assessment adapter now sends the caller's actual JSON Schema to
Ollama, honors its token budget, checks the completion reason, and retries a
truncated structured response once with a larger budget. Both attempts share
one deadline. It never repairs or accepts partial JSON. Program assessments
also validate nested fields before ranking. Error logs omit generated text and
provider response bodies. The configured `AUTOHACK_OLLAMA_URL` is shared with
the source-reading agent; `OLLAMA_MODEL` selects the assessment model, falling
back to `LOCAL_OLLAMA_MODEL` and then qwen3:4b.

Run `bash scripts/verify-assessment.sh` to exercise the actual program assessor
with the configured local model and fictional source-scope data. This performs
only local model inference, with no repository clone, target request, provider
call, database update or submission. Host/model acceptance now includes this
check when `OLLAMA_DISCOVERY_DIRECT=true`. CI covers schema propagation,
truncation and exhausted budgets, malformed/nested output, HTTP failures,
request deadlines and queue recovery through the production adapter.


Program assessment output is now grounded in the displayed scope entries.
Its response schema enumerates exact asset identifiers and types, bounds the
number of targets, and enumerates counts no larger than the supplied distinct
asset set. Independent validation rejects invented asset/type pairs, duplicate
targets, empty target selections and inconsistent counts before ranking. Empty
scope data produces zero targets without inference. These assessment hints do
not replace the solver's separate eligibility and exact-scope authorization.
The real assessment fixture retains exact asset checks and requires its one
supplied repository to be the single selected target with a count of one.

## Existing runtime repair checks

The aggregator adapter requests the supported Bugcrowd, Intigriti and YesWeHack
JSON feeds, with a 30-second deadline per request. The nonexistent Federacy data
file is no longer requested. The former Huntr repository feed at `/bounties` is
unavailable; its adapter logs that state and returns no programs instead of
inventing repository eligibility or rewards from page links.

A native local-model hunt requires at least one successfully acquired eligible
source repository. Acquisition failure stops before inference. Acquisition and
incomplete-model failures preserve the last completed hunt timestamp, hunt count
and miss streak, and propagate to the orchestrator's existing error backoff.
Failed dispatches still consume the existing daily dispatch quota.

Run
`python3 scripts/acceptance.py --offline` with Node 22 selected for the offline
regression suite. It includes service reinstall tests using a fake systemctl,
intercepted discovery requests, and temporary SQLite hunt-history tests with
fake Git and model responses. No real bounty assets or submissions are used.



## Local integration repairs after the connection commit

A local hunt now records coverage independently from findings. Missing or failed
reproduction infrastructure is a failed attempt; a model answer without any
completed supported probe is incomplete coverage (failed or unsupported). Neither advances completed
hunt history. Completed negative probes may produce a valid empty finding list.
Coverage details and retry state remain in the program scope-summary metadata.
This is bounded inspection coverage, not a claim that an entire repository is
free of vulnerabilities.

Review acquires the exact recorded source commit before verifying source hashes
and replaying its observations. Pending local reviews and confirmed submission
receipts are recovered at startup and every minute while automatic hunting or
submission is enabled. Manual and cautious completed reviews wait for operator
action. Existing uncertain/rejected outbox entries are not resubmitted.

Local cancellation spans the complete hunt or review queue, including Git and
Python subprocesses. Cancellation stops further review items and prevents a new
submission from starting; a submission already in flight retains its outbox
state and receipt handling. The job keeps its lock through cleanup and history
updates. Dead-process hunt locks are reclaimed under an immediate SQLite
transaction during normal acquisition, not only at startup.

Hunter and independent reviewer responses must provide severity, confidence
and an evidence-based rating explanation. Ratings are validated and reviewed
against configured thresholds; no fixed medium/0.8 rating is assigned.

These edits were published without executing tests or CI at the operator's
request. The existing hunt-failure regression was updated to the current local
workspace paths, JSON response contract and incomplete-coverage behavior.


## Tomey Gun desktop launcher

After verification and user-service installation, run:

```bash
bash scripts/install-desktop.sh
```

This installs the Constanzo icon and Tomey Gun entry in your application menu
and desktop directory (when desktop icons are enabled). If prompted, right-click
the desktop icon and choose Allow Launching. Re-run the installer after moving
the checkout so the shortcut points to its new location.

Opening Tomey Gun starts `autohack.service` if needed, waits up to 60 seconds for
the configured local dashboard, then opens it. Chrome or Chromium opens a
dedicated app window with a separate browser profile; otherwise the default
browser opens the dashboard. This is a launcher for the existing local service.
Closing its window leaves the service running. Use the shortcut's Stop Tomey Gun
action or `systemctl --user stop autohack.service` to stop it. The laptop must
remain powered on and awake for the service to run.


### Local assessment timeout

Direct Ollama program and finding assessments honor
`OLLAMA_ASSESSMENT_TIMEOUT_MS`. The default is 600000 ms (10 minutes); valid
values are integer milliseconds from 1 through 1800000 (30 minutes). Set this
in the checkout's `.env` and restart `autohack.service` to apply a change.
An existing explicit value such as 180000 continues to override the default.
The dashboard's hunt timeout is a separate setting. The assessment deadline
starts after the process-local Ollama queue is acquired and covers both output
attempts together. The configured deadline is recorded in assessment-start logs.


### Imported static leads

With automatic hunting enabled, the orchestrator checks imported `offline-` leads
without an Accept click. Python leads are passed to the existing source-function
investigator at their recorded repository commit and file, subject to current
program eligibility, scope, daily quota and the shared hunt lock. Qualifying
reports become separate findings with `originLeadId` and pass through normal
independent replay/review. The original static lead stays unverified.

The existing reproduction driver supports only Python string functions for
HTML reflection and path construction. JavaScript, Solidity and other languages
are marked `unsupported`, with the reason displayed in the finding. This repair
does not add reproduction support for those languages or claim that these
heuristic matches are valid vulnerabilities. Infrastructure/model failures stay
unverified and retry with backoff. Unsupported leads are retained for future
engine support; they are not automatically rejected as false positives.

Generic finding assessment and manual Accept cannot promote imported leads or
erase their provenance. The legacy finding-solver path does not handle them.


### Long-running Ollama HTTP replies

Both local assessment and tool-using audit calls use Node's HTTP/HTTPS client
with the caller's abort deadline covering connection, response headers and body.
This avoids fetch/Undici's independent headers timeout ending a valid model call
before the configured assessment or audit deadline. Redirects are rejected, TLS
validation stays enabled, and response bodies are limited to 1 MiB.
A longer deadline permits slower responses; it does not improve model throughput.


### Assessment scope selections

The program assessor asks the model for integer `scopeId` row selections rather
than asset URLs, asset types, or an independently estimated target count. The
application resolves each selected ID against the exact supplied scope table,
retains the original asset/type pair, removes repeated asset selections, and
sets `targetCount` to the selected distinct asset count. Unknown IDs and malformed
responses are rejected. The stored assessment shape is unchanged. Selection
IDs are metadata references; they do not establish authorization for testing.


### Empty hunt queue: inspect the selection funnel

Run `node --import tsx scripts/diagnose-progress.ts` from the checkout after loading
`scripts/node-runtime.sh`. This opens the existing configured database read-only;
it does not initialize or migrate it, launch inference, fetch targets or submit reports.
It prints only selected nonsecret settings, daily dispatch totals, mutually exclusive
first-blocking reasons by provider, recorded coverage and static-investigation states.
The report uses the same selection gates as dispatch. The scheduler now logs these
counts whenever no program is eligible, instead of assuming assessments/cooldowns.
A missing assessment, a completed zero-opportunity assessment, and a ranking reduced
to zero by reward/response efficiency are separate reasons. Counts explain selection,
not whether a discovered repository is supported by the reproduction engine.

`signal_required` applies to nonlocal hunting when the program advertises a threshold
and the operator enabled `SKIP_SIGNAL_REQUIRED`; it does not establish this researcher's
account eligibility. Local source-only assessment/inspection no longer treats this
submission setting as a research ban. The local submission path still fetches the
current requirement and holds the report when the skip setting applies.
Zero and negative thresholds remain actual requirements. Missing fields, malformed
values and partial GraphQL errors are inconclusive and preserve the existing database
value. This repair does not guess account Signal, consume trial reports or disable
operator filters. Official reference:
https://docs.hackerone.com/en/articles/8505319-signal-requirements

The local reproduction path remains limited to Python string-in/string-out HTML
reflection and path-construction probes. JavaScript, Solidity and Go static leads do
not acquire reproduction support merely by passing selection or assessment.


### Signal does not block local source inspection

The shared candidate filter used to exclude every Signal-required program before
local assessment or repository inspection. When discovery marked all HackerOne
programs as Signal-required, this removed the entire provider from the local queue.
For the local source-only model path, that early Signal exclusion has been removed.
Provider enablement, explicit scope, reward, source repository, exclusions, prior-hunt
policy, cooldowns and retry limits still apply. The nonlocal hunt skip policy and the
fresh Signal check immediately before local automatic submission remain in place.
This change permits inspection; it neither asserts account submission eligibility nor
consumes trial reports. Existing explicit per-call assessment filters are preserved.


### Imported hunt timestamps do not establish local coverage

With `SKIP_PREVIOUSLY_HUNTED` enabled, local source selection skips a previous hunt
only when `scopeSummary.huntCoverage.status` is `completed` at the current capability
version. Bounded local passes are `partial`. An older installation's
timestamp without a completed coverage record is eligible for another local inspection
after the base cooldown/backoff. An unverified legacy miss streak does not multiply
that cooldown into days of delay. No timestamps, hunt counts, findings or research history
are erased. Nonlocal selection retains its existing prior-hunt behavior. Unsupported
and failed inspections still use the existing bounded retry backoff; this change does
not label them successful or create reproduction support for additional languages.


## Reliability repairs: bounded inspection and recovery

Local source audits now record `huntCoverage.status: partial` after a successful
bounded pass. A supported probe is evidence about that function, not completion
of a whole program. Partial passes retain the normal cooldown but do not trigger
`SKIP_PREVIOUSLY_HUNTED` or an escalating no-finding penalty. Legacy completion
records from earlier capability versions are revisitable. `inspectionPass`
advances even after failures and rotates the two-repository acquisition batch,
so repositories beyond the first two are eventually selected. Existing inspection
checkpoints still carry context between passes on the same revision.

Zero completed probes is `failed` if a probe failed or no probe was attempted;
it is `unsupported` only if there were unsupported probes and no failed probes.
Neither result permanently excludes an entire program. Both use bounded failure
backoff. Imported supported-language leads also retry incomplete investigations.

Read and listing tools expose `nextOffset`; source reads use character offsets,
listings use entry offsets, and searches use file offsets within the selected path.
Search results explicitly describe incomplete coverage and excluded directories.
Search now includes `.mjs` and `.cjs` and traverses deep directories. The hunter
and independent reviewer must read the entire claimed caller line, rather than
merely opening the beginning of that file.

Quota claims occur under the shared hunt lock. Busy and quota-denied attempts do
not consume a new slot or modify hunt history. Quota and outbox JSON writes are
serialized by separate SQLite mutex databases; the OS releases transaction locks
if a writer crashes. Existing pending/uncertain submissions remain pending/uncertain
and are never automatically resent as a consequence of lock recovery.

**Upgrading from ownerless lock files:** stop the old orchestrator and dashboard
before upgrading. If a prior crash left `data/hunt-daily-quota.json.lock` or
`data/submission-outbox.json.lock`, remove only those stale lock files after all
old writers have stopped. The new implementation reports the exact legacy lock
path rather than guessing whether an old writer is alive. Keep the JSON stores
and the new `*.mutex.sqlite` files. New-version crashes require no lock-file cleanup.

HackerOne discovery retries missing scopes, refreshes populated scopes daily,
reactivates returning archived programs, and preserves paused programs and current
assessment/hunt metadata. Report polling continues for accepted and rewarded
reports, records late or additional awards without requiring a status transition,
and leaves the separately verified cash ledger unchanged.
