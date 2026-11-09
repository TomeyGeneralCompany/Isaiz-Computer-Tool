# Production execution boundary repairs — 2026-11-09

Baseline: ce0b12ef98644c08dfc9ba97b4fa9d3bc5e81567.

## Evidence and execution paths

The dashboard/orchestrator and one-bounty entry paths reach `runProgramHunt` in `claude-runner.ts`; local-model operation delegates to `runLocalProgramHunt`. That path acquires authorized repositories, inventories supported source, constructs controller candidates, invokes `runLocalAudit` when deterministic entry evidence is insufficient, records cases through `createProbeSession`, and constructs reports. `independentReview` reacquires the recorded commit and replays cases before technical review. Stateful observations remain observations and cannot become security proof through an expected-value mismatch.

Historical evidence inspected: laptop workflow 42536451886 (job 128901728759), the linked failure #178, PR #179 and its failing then passing checks, current PR #180, and the four automatic PR workflow definitions. The laptop job reached actual investigation; its step times show 23:44–03:26 execution. The ticket must not be interpreted as proof that setup failed. PR #179 already contains request deadlines and retries; this change preserves that behavior.

## Independently inspected language boundaries

| Language | Defect and consequence | Repair and regression |
| --- | --- | --- |
| Python | The production session's extension regex required a literal backslash. Valid `.py` stateful plans were rejected before execution. The runner had the same error in intent canonicalization and recovery filters. | Validate ordinary extensions; exercise the real session schema, source-based intent correction, same-instance execution and independent replay. |
| JavaScript | The same regex rejected `.js`, `.cjs`, and `.mjs` sequences and disabled source-based intent canonicalization. | Cover all three extensions and reject mismatched source languages; execute and replay a CommonJS factory sequence in isolation. Import/re-export lines cannot be borrowed as multiline caller evidence. |
| Java | The driver correctly returns `unsupported_execution` for unsupported signatures, but the shared session treated it as a fatal infrastructure failure, poisoning continued investigation. The canonicalization filter also excluded ordinary `.java` paths. | Count unsupported execution separately, retain no case or completed-test credit, keep the session available, and verify source-generated primitive state plans reach the exact selected method. |
| Solidity | The indexed runner rejected a controller-locked verified case even when the only permitted action was final assessment. | Permit a final-only transition with no pending probe, including a verified focus. Preserve exact controller-selected plans and test the transition alongside all other languages. |

The final-handoff contradiction duplicates the repair proposed in PR #180. This branch covers it with execution-level runner regressions rather than testing source-string formatting.

## Shared evidence and CI defects

Several controller event writes used a literal `\\n` instead of a physical newline. Successive events then occupied one physical line, breaking anchored log consumers and obscuring progress. Normalize event separators in both production runner files. JSON-escaped newlines inside evidence payloads remain ordinary JSON data.

Historical fidelity dispatch preserved the canonical harness twice in one job and never preserved it in the isolated job. Checkout can clean the original harness directory. Preserve the harness once per job before checking out the evaluated revision.

## Verification boundaries

`test-source-probe-session.ts` exercises the production schema and real unsupported-signature result. Its `--isolated` mode executes stateful Python and JavaScript probes and independently replays the saved cases; it is required in the GitHub-hosted source-reproduction workflow. `test-controller-verified-handoff.ts` injects verifier responses to isolate scheduling and canonicalization behavior in all four languages. These injected responses are unit-test data, not reproduction or real-world-success evidence.

The existing real isolated four-language corpus, indexed entry tests, independent review tests, real-Qwen acceptance and production fidelity workflows remain required. No reproduction, reviewer, scope or submission gate is relaxed. The local container could install dependencies with scripts disabled and run TypeScript/offline checks, but its native SQLite build failed while extracting Node headers. Native integration and actual isolated-runtime acceptance must therefore be established by GitHub-hosted CI, not inferred from local unit results.

This repair set does not establish that arbitrary real-world investigations will now succeed. Existing candidate adapters remain bounded and source-pattern-specific; full-source inventory does not imply complete supported execution or complete vulnerability coverage. The final live investigation remains a separate validation step.
