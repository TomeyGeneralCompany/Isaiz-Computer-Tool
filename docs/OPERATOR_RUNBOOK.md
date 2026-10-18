# AutoHack operating and verification guide (October 18, 2026)

## Current boundaries

CI exercises explicit scope denial, a real local source read via a mocked Ollama
tool conversation, deterministic replay on an owned vulnerable fixture, report
generation, the actual HackerOne request serializer intercepted in memory,
rejection behavior, duplicate prevention, and persistent submission recovery.
It sends **no** synthetic reports to real programs and makes **no** external
target requests. CI does NOT demonstrate live end-to-end autonomous hunting.

The native Ollama agent remains read-only. It may clone up to two explicitly
eligible public GitHub SOURCE_CODE repositories into its private workspace.
The separate scoped HTTP observer library only allows GET/HEAD with exact
scope, rate limit, total request budget, public IPv4 DNS pin, and disabled
redirect following. This observer is not yet exposed as a local Ollama tool.

## Setup / operations

1. On the CPU-only Linux host, use Node.js 22+, npm, Python 3 and Git.
2. Store platform keys and model settings in a local .env (0600); never commit secrets.
3. Run: bash setup-and-run.sh
4. Open dashboard on http://127.0.0.1:3456 (loopback only).
5. Test the actual local model: npx tsx scripts/test-local-agent.ts
6. Confirm the actual SQLite native addon builds: npm ci (not --ignore-scripts).
7. Run the full service under a restart-capable process manager after host validation.

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

    npm ci --ignore-scripts
    npx tsc --noEmit --project tsconfig.json
    npx tsc --noEmit --project packages/dashboard/tsconfig.json
    npx tsx scripts/test-mock-agent.ts
    npx tsx scripts/test-earnings.ts
    npx tsx scripts/test-scope.ts
    npx tsx scripts/test-daily-quota.ts
    npx tsx scripts/test-submission-outbox.ts
    npx tsx scripts/test-mock-submission.ts
    npx tsx scripts/test-scoped-http.ts
    npx tsx scripts/test-offline-end-to-end.ts
    python3 -m unittest discover -s tests -p 'test_*.py' -v

The CI runner uses --ignore-scripts to prevent native package builds; it can
typecheck and run self-contained integration mocks, but it CANNOT establish
that the actual better-sqlite3 native binding and local Ollama model work.
Run npm ci without that option on the host and validate dashboard, SQLite,
and real model before production deployment.

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
