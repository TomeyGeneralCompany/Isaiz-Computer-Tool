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
eligible public GitHub SOURCE_CODE repositories into its private workspace.
The separate scoped HTTP observer library only allows GET/HEAD with exact
scope, rate limit, total request budget, public IPv4 DNS pin, and disabled
redirect following. This observer is not yet exposed as a local Ollama tool.

## Setup / operations

1. On the CPU-only Linux host, use Node.js 22, npm, Python 3, Git and flock (util-linux).
2. Store platform keys and model settings in a local .env (0600); never commit secrets.
3. Run: bash setup-and-run.sh
4. Open dashboard on http://127.0.0.1:3456 (loopback only).
5. Verify the host and read-only provider access: bash scripts/verify-host.sh
   This saves private evidence in data/host-acceptance.json and returns nonzero
   for any failed check. It never submits a report. Stop a running AutoHack
   instance before this check so the isolated restart smoke can bind port 3456.
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
