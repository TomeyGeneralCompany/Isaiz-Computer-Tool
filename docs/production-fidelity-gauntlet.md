# LOTUS Production Fidelity Gauntlet — design and implementation contract

This suite complements the Level 6 stress gauntlet. It is **not** a substitute for PR160's complete responsibility-matrix implementation, and its existence does not imply passing tests.

## Objective
Reproduce production behavior with the same production runner, controller, verifier, independent reviewer, persistence, and report pipeline. Mock only external infrastructure and deliberately controlled semantic answers. Do not build a separate simplified test controller.

## Corpus dimensions
- 0, 1, 8, 24, 48, 49, 80, 200, and 2,000+ eligible files.
- Source types in Solidity, Java, JavaScript, and Python; common controller invariants in every language.
- Different ratios of actual security-relevant contracts/modules to test fixtures, deployment scripts, generated code, libraries, and decoys.
- Short files, files requiring multiple 2,000-character pages, source outlines, caller chains spanning files, and indexed reads.
- Realistic source ranking that puts security-relevant production code both early and late in the queue.
- Candidates with valid probes, candidates requiring semantic ambiguity assessment, false positives, and repositories with no executable candidate.

## Reproduce the observed 88mph failure
- 48 eligible files with ranked reads and 2,000-character page progression.
- Controller transition from inspect to hypothesize after initial source reads.
- Exhaustion of a small candidate queue without a supported probe.
- A model response proposing finalization without verified case IDs.
- A malformed/non-JSON model response and repeated finalization attempts.
- Verify controller never delegates mechanical action selection, never loops through rejected finals, and terminates with an evidence-backed finding or explicit deterministic exhaustion state.
- Verify each candidate rejection has a reason and no remaining eligible work is silently abandoned.

## Common invariant assertions (all four languages)
1. Model cannot choose repository, file, offset, declaration, caller, probe arguments, probe execution, or finalization timing.
2. Every source page and candidate is tracked across context compaction and restarts; no reread without explicit controller justification.
3. Probe execution is isolated; verifier independently records inputs, outputs, case IDs, and source-to-impact evidence.
4. Bounded Qwen semantic responses contain only a structured assessment tied to evidence IDs; malformed, adversarial, or unauthorized responses cannot change workflow state.
5. Final assessment includes independent review. Controller assembles factual report; Qwen prose cannot introduce new claims.
6. No unsupported findings, no fabricated case IDs, and no evidence-free finalization.
7. Both small and large repositories progress without a fallback to model-directed workflow.
8. The suite records exact action origin, queue state, page cursor, candidate decision, probe case ID, reviewer verdict, and terminal reason.

## Test execution and release
- Run deterministic fixture-based regression on each PR, using production code paths.
- Run cross-language matrix with same invariants, not language-specific exceptions.
- Compare emitted traces to approved event-level expectations, not just a final pass/fail.
- Keep Level 6 as a separate stress suite. A real-world one-bounty trial remains an independent validation, not something the lab can guarantee.
- PR160's full matrix must be implemented and verified independently; do not claim this document implements the gauntlet.
