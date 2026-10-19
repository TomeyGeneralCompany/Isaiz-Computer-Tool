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
