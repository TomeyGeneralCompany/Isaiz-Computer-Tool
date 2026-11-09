# Production architecture and implementation audit

Baseline: `608fa4acdcd7b35179c52d5fd8cb5fec612c9783` (merged PR 181).
Repair branch: `fix/comprehensive-production-audit`; PR 182.

## Execution contract

A source inventory, a proposed probe, a runtime observation, a security finding, and permission to submit are separate controller states. No filename, lexical match, model assertion, assertion mismatch, or passing routing mock establishes a reproduced vulnerability. The independent reviewer must reload the authorized commit and replay recorded cases. This audit preserves these requirements.

Production source entry points are the dashboard/orchestrator and `one-bounty.ts` through `huntProgram` / `runProgramHunt`, including focused static leads. Source-bearing scopes now use `runLocalProgramHunt` even if `LOCAL_OLLAMA_MODEL` is absent. Inference configuration cannot select the legacy free-form source investigator or report rewriter. Existing non-source backends are distinct legacy paths. Persisted reproduction cases always use the local independent-replay review queue, including after a backend environment change. Cancellation retains the active controller's lock until cleanup completes.

The source path is authorized acquisition → capability inventory → static leads / full controller index → source declarations and caller evidence → controller-owned plan → isolated execution → persisted case → source-linked report packet → fresh independent acquisition and replay → technical review → separate submission gates. Scope, source revision, evidence hashes, replay consistency, negative controls, quality thresholds, and submission policy remain enforced.

## Recorded failures and causal findings

- Laptop run `42536451886`, job `128901728759`, issue 178: `SETUP_OK`; the real 88mph investigation reached turns 75–76 after repeated completed `SafeERC20.sol` reads and source handoffs. The last request stalled before a new action. Its archived logs and terminal transcript confirm investigation failure rather than setup failure. Existing request cancellation/retry and controller source bypass from PR 179 remain in place.
- Six-level run `42632036416`, Solidity level 1 job `129210493602`, artifact `13685657371`: the actual EVM probe recorded unauthorized `SettlementAuthority.rotateOperator` behavior at turn 2, then the hunt spent the remaining 80-turn allowance requesting completed source and never reached independent review. The callback's send predicate was reversed: a matching mined send returned no authoritative handoff, while absence of that send selected the handoff. Correct the predicate. Existing source/probe/review checks remain mandatory.
- The full-index scheduling policy was enabled by the laptop shell wrapper but not by ordinary production callers. Thus superficially similar tests and launches could exercise different controller authority. Enable production full indexing and controller scheduling by default, passing the policy explicitly into the runner. Explicit legacy comparison mode remains available for fixtures.
- Candidate discovery and scheduling selected the first supported method per file repeatedly. An unsupported or negative method could conceal a later supported one; Solidity attempted the same state method with only a changed hypothesis. Enumerate source-grounded plans and exclude already attempted path/selector/kind tuples. Correct canonicalization to consider every HTML declaration in the selected file, so later Java methods are not silently converted to another adapter.
- An exhausted queue with genuine observations but no locked case had no controller-owned assessment transition. It either threw an unresolved-action error or returned to model-selected navigation. Add an explicit final-only transition after every ranked source reaches its terminal page and no controller-selected plan remains. An empty queue without an execution still fails as incomplete; it cannot become synthetic success.
- Queue exhaustion was checked before remaining pages, so a file marked read after its first page could lose its unread continuation. Move exhaustion checking after controller-owned page continuation. Match exact source keys when recovering offsets, rather than substring matches between similarly named files.

- Solidity AST limits were cumulative across the entire audit: after 32 unrelated files, subsequent declarations became permanently unavailable even when each source was small. Apply file/graph limits to each operation and retain the bounded content-hash parser cache. A regression traverses 40 sources exceeding 4 MB cumulatively without expanding any individual graph limit.

## Independent language inspection

| Language | Inspected implementation boundaries | Repair and validation |
| --- | --- | --- |
| Python | Capability inventory, top-level declaration and typed stateful factory discovery, import-resolved caller chains, entry handler adapter, same-instance runtime, observation classification, recorded-case replay, review | Enumerate remaining methods; accept explicit primitive annotations/defaults and both single-line and multiline factories without evaluating source expressions. Typed defaults become declarative data. Hosted isolated session tests execute and replay the annotated factory. |
| JavaScript | CommonJS/ESM declaration discovery, factory/method plans, module loading, dependency preparation, async return handling, entry output, same-instance state observations, replay and review | Enumerate remaining declarations; preserve source-declared primitive defaults; fix arrow-factory constructor parameter extraction. Accept exported ESM factory declarations at the Python executor's factory validation boundary. Hosted tests execute and replay an actual `.mjs` factory. |
| Java | Primitive/String constructors and methods, one-input text adapters, overload rejection, source dependency/caller resolution, actual JDK execution, entry output, replay and review | Enumerate all grounded Java plans, preserve exact selected methods through canonicalization, and move beyond unsupported first methods. Existing unknown-type and ambiguous-overload rejection remains unchanged. Four-language routing regressions include separate Java assertions; hosted jobs compile and execute actual Java cases. |
| Solidity | Compiler compatibility, AST declarations/getters, source role candidates, ABI-backed transactions, before/after state, protected consumer evidence, direct transaction handoff, fresh EVM replay and independent review | Correct inverted direct-send handoff, prevent repeating completed methods, and preserve controller source progress through review. The changed level-1 path must execute the actual EVM case and pass independent review; routing mocks do not satisfy it. Existing protected-consumer positive/negative EVM tests remain required. |

The supported adapters remain bounded. Unknown signatures, dynamic dispatch, unavailable dependencies, ambiguous imports/overloads, unsupported compiler versions and unproved deployment effects remain explicit capability/evidence gaps. These limitations must not be classified as completed whole-program audits or security proof.

## Evidence persistence and context

1. Checkpoint references were restored into a new run although their IDs referred to the previous log's archive. The next retrieval could fail with a missing evidence reference. Preserve prior navigation notes as untrusted context, but require new reads and probes and retain only current-run evidence IDs.
2. Initial prefetch probes were archived, but ordinary source/probe tools were not consistently recorded in the cold archive. Archive every ordinary delivered source page and ordinary probe outcome, including failed/unsupported results. These entries retain their actual classification; they are not upgraded to security evidence.
3. The runner credited a source range before adding a declaration menu and fitting the serialized tool output again. A shortened delivered page could be credited as the longer original. Credit read spans, terminal state and cursors only after the final fit. Tests compare archived delivered text length and spans with the controller's read callback.
4. Independent review evidence was written under a temporary checkout deleted in `finally`. Keep its route, original replay, packet and decision in a durable archive beside the review log. Deterministic factual review decisions now receive the same persisted decision record as model review decisions.
5. Snapshot parent ID arrays on append, verify parent existence/order on reload, verify metadata as well as payload hashes on retrieval, and return retrieval snapshots so callers cannot mutate authoritative cold records.
6. Preserve cancellation through indexing catches. A cancelled read must not be converted into an ordinary skipped file.

## Verification protocol

`test-production-audit-regressions.ts` injects outcomes to isolate four independent scheduling paths, unsupported-first progression, negative-only assessment, exact delivered source ranges, archived ordinary probes, and restart references. Its results are unit evidence only. `test-production-source-routing.ts` verifies all four source scopes retain controller authority without a model environment override and cannot fall back to free-form report rewriting.

`test-source-probe-session.ts --isolated` executes and independently replays real Python and JavaScript stateful cases, including typed Python and an ESM arrow factory. Existing suites compile Java, execute Solidity transactions, exercise entry-to-output paths, validate review source chains and secure controls, and run Qwen against the production controller.

The added `production-audit-qualification.yml` runs levels 1–6 independently for Solidity, Python, JavaScript and Java on GitHub-hosted runners. Each job uses the production investigator and existing isolated execution/review grading. It does not replace execution with test doubles, alter grading, consult the private answer key during investigation, or enable external submission. Qwen smoke is also required for solver/executor changes.

Local environment: native SQLite was rebuilt successfully using the matching Node headers. TypeScript, routing, controller, archive, context, review-chain and Python non-integration suites can run here. Nested sandbox execution fails at this container's process namespace boundary (`bwrap: open /proc/.../ns/ns failed`), so local sandbox attempts are not counted as passing integrations. GitHub-hosted isolated execution is mandatory. The self-hosted laptop is reserved for final real-world validation after the verified merge.

Final acceptance records are the checks attached to the exact final PR head, followed by the authorized real-world run. Earlier passing heads and individual successful jobs cannot substitute for that acceptance.
