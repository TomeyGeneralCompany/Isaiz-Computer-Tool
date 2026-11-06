# LOTUS controller feature-parity contract

Source of truth: production Solidity controller at `packages/security-solver/src/local-ollama-runner.ts`, `solidity-source-index.ts`, `solidity-probe-inputs.ts` and the shared source/review pipeline. **No language earns release approval from component-level CI alone.** All four languages must pass one full Gauntlet run on one commit.

The model may suggest hypotheses, but it does not get to invent selectors, constructor or method arguments, source paths, evidence IDs, source lines, observed effects, immutable replay results, or an independently unobserved mitigation. A controller failure is an incomplete investigation, not a fabricated finding.

## Mechanism inventory and required equivalents

| Mechanism found in Solidity | Solidity implementation | Java, Python and JavaScript equivalent | Verification and remaining limitations |
|---|---|---|---|
| Authorized acquisition and immutable target revision | `local-program-flow.ts` acquisition + repository commit | Same shared acquisition, no second trust boundary | Scope, commit and dependency checks used for every language |
| Source discovery, bounded navigation and prioritized target reads | `SoliditySourceIndex` AST/outline, `source-candidates.ts` | Shared source map, paged file reads, `source-guided-probes.ts`, `controller-source-candidates.ts` | Solidity has an AST/inheritance index; non-Solidity helper binding remains conservative/incomplete |
| Source-owned exact function/selector discovery | `SoliditySourceIndex.probeMenu` | `probe-target-validation.ts`, `controller-polyglot-plan.ts`, `controller-java-probe-inputs.ts` | Unsupported or ambiguous declarations fail closed |
| Deterministic constructor and method fixture arguments | `fixtureArguments`, `buildBaselineSequence` | `controller-java-probe-inputs.ts` typed Java fixtures; `controller-stateful-candidates.ts` Python/JS bounded factory arguments | Constrained to safely inferred primitive/string types and source-declared factories |
| Stateful before/after observations | Solidity `observe/send/observe` | Java getter/mutation/getter, Java/Python/JS same-instance method steps | Not a security finding without demonstrated unauthorized effect |
| Model request canonicalization, wrong-kind correction, recovery | `local-ollama-runner.ts` `PROBE_BASELINE_CONSTRUCTED`, `PROBE_REQUEST_CANONICALIZED` | `canonicalControllerPolyglotIntent`; source-backed declared selector and controller-created sequence, shared `controllerOwnedNextAction` | Never substitute an unrelated method for an invented selector |
| Controller-owned execution, sandbox isolation and errors | Source reproduction dispatcher | Same `source-reproduction.ts` with Java/Python/JS adapters | Unsupported dependencies/complex setup are recorded, not bypassed |
| Persistent SHA/source/evidence/case IDs | `SourceCase`, source digest and case store | Same language-neutral source case store; Qwen does not assign case IDs | Replay equality required |
| Verified upstream callers and concrete entry execution | Solidity actual direct transaction and sender; `validReachability` | Import-resolved `controllerCallerChain`, `promoteControllerCallChain` and executed `entry_html_reflection` for Java/Python/JS | Runtime handler entry applies to tested HTML paths; general app entry/sink coverage is incomplete |
| Model-independent provisional finding construction | `local-program-flow.ts` case normalization and `controller-report-narrative.ts` | Shared controller proof candidate, case promotion and report packet for supported executed entry paths | No source-grounded case -> no finding |
| Immutable final report facts, scope and source/caller provenance | `controller-report-packet.ts`, deterministic report builder | Same path for every source kind and language | Model impact prose must not replace reproduced facts |
| Fresh independent replay | `independentReview`, `replaySourceCase` | Same code, same commit and equality check across languages | No independent replay -> no technical approval |
| Reviewer's factual authority bounded by evidence | Controller source/replay checks in `review-evidence-chain.ts` and `entry-review-evidence.ts` | `controller-review-boundary.ts` immutable fact ledger, replay/entry contradiction gate, deterministic **local** HTML-injection classification | Broader exploitability still requires concrete source/runtime proof; do not infer XSS or reportability |
| External submission and severity protection | `processLocalReviewQueue`, outbox and eligibility thresholds | Same shared pipeline for all languages | Local technical verification always means `dont_submit` unless stronger independent impact proof exists |

## Release gate

1. Each implementation change passes exact-head static checks, source reproduction, and actual Qwen3 production controller acceptance. These component checks do **not** equal full system acceptance.
2. Run a fresh single-commit Level-5 MAX Gauntlet for Solidity, Python, Java, and JavaScript. **4/4 verified findings is the acceptance condition**.
3. Every result preserves the actual source and case hash, observed probe/replay, verified caller and reviewer decision. A model's wording is not a substitute.
4. If any language fails, record the exact first divergent mechanism, fix shared code where possible, and rerun all four. Do not use seeded answer-key information to create findings and do not weaken the independent runtime evidence requirements.
5. For real programs, a local HTML-injection observation without production route, response context and exploitable impact is technical source evidence **only**, not an authorized bounty report. All external submissions remain subject to policy, severity and independent impact gates.
