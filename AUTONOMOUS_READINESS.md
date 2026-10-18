# AutoHack — operational truth and completion criteria

Last updated: 2026-10-18.

## Verified in user terminal
- SQLite schema exists (security_findings and security_programs).
- Python fixture and importer tests: six passed.
- TypeScript typecheck passed at commit 5ea85d9.
- Ollama qwen3:4b responds to its native /api/chat endpoint.
- Claude Code through Ollama's Anthropic-compatible bridge **does not work**; it times out.
- The original full autonomous hunt/review/submit workflow has **not** passed an end-to-end test.

## Changes in repository
- Local solver routes to native Ollama /api/chat when LOCAL_OLLAMA_MODEL is set.
- Local model has bounded, read-only file inspection and literal search tools.
- Agent fixture must record an actual read_file invocation.
- Mock Ollama test exercises a tool-use round trip without depending on installed models.
- The local-model review path cannot auto-submit to HackerOne. Offline imports also cannot auto-submit.
- No remote targets are probed by the acceptance tests.

## Known limitations
- Native Ollama agent has no live HTTP probing, execution, debugger, or sandboxed PoC runner.
- The original Claude agent's tools and capabilities have **not** been ported.
- Program discovery, source acquisition, local analysis, verification, drafting, reviewer, and HackerOne submission have **not** been exercised together.
- A model response is not proof of an exploitable vulnerability.
- CI passing does not mean the local model or live bounty workflow works. The latest verified baseline is commit d8cb799; later changes require their own check results.

## Implemented on development branch (2026-10-18)
- Repaired malformed GitHub Actions workflow and local Ollama literal search/newline parsing.
- Added explicit eligible URL/repository allowlist, fail-closed program selection, out-of-scope finding rejection, and scope assertion before both automatic and manual submission.
- Added separate bounded GET/HEAD observer with public IPv4 pinned DNS, request budget, response size and timeout caps, rate limiting and no redirect following. Not yet exposed to local model or verified against live target.
- Added local read-only source acquisition limited to two explicitly eligible public GitHub source scopes; actual host checkout remains untested.
- Added at-most-once submission outbox with persistent states and conservative ambiguous-failure handling. An intercepted actual HackerOne report serializer test checks payload, rejection and duplicate prevention.
- Added durable per-UTC-day hunt dispatch quota, idle pause responsiveness and error backoff, plus loopback-only dashboard binding.
- Added operator-reconciled USD payout ledger; dashboard separates actual verified paid receipts from unreconciled rewarded findings and pending reports. Configurable default monthly goal = $4,000 (not a guarantee).
- Added a full offline *toy fixture* test: scoped program -> model read_file tool -> deterministic local replay -> evidence digest -> report -> evidence review -> intercepted/mock submission -> persistent recovery. This is not proof of live end-to-end bounty functionality.
- Added operator runbook with exact setup, reconciliation, safety and remaining acceptance gates.

## Required before calling complete
1. Implement scoped, rate-limited investigation tools restricted to explicitly authorized program assets, and test denied targets.
2. Implement sandboxed reproducible verification, retaining command/output evidence and distinguishing source hypotheses from runtime-confirmed issues.
3. Exercise a full program -> finding -> verification -> report -> review workflow against an isolated, intentionally vulnerable fixture.
4. Mock the HackerOne endpoint and verify the submission payload, program scope, duplicate checks, idempotency, and rejection behavior. Never submit a synthetic finding to a real program.
5. Run TypeScript and deterministic integration tests on CI and run the local Ollama agent fixture on the actual CPU-only host.
6. Validate restart/recovery, scheduling, queue limits, and safe unattended failure behavior.

## User setup
The existing entry point remains `bash setup-and-run.sh` from the repository root. Do not interpret a successful installer as proof that the complete bounty workflow is ready.

## Policy
Operate only on assets authorized by the published bounty program, within rate limits and restrictions. Never submit unsupported or synthetic vulnerability claims.

## Host handoff completed in source (October 18)

The host entry point is `bash scripts/verify-host.sh`. It checks configured
Ollama availability and actual tool use, runs the owned end-to-end fixture with
the actual model, tests read-only HackerOne authentication, and saves a private
JSON report. These checks are prepared for the host; a development fixture is
not represented as a passed real-model or real-provider check.

Node 22 selection is shared by setup, launch and systemd. Duplicate launch
locks and real dashboard restart checks cover normal local supervision.
Review cloning no longer uses shell interpolation or URLs from report prose;
only eligible source scopes can supply an acquired repository.
