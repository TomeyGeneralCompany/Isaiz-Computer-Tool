# PR 160 — mandatory complete responsibility matrix

This document is a binding implementation and verification checklist, **not evidence that implementation is complete**. No partial merge.

| Stage | Exclusive owner | Required enforced behavior |
|---|---|---|
| Repository discovery and indexing | Controller | Deterministic enumeration, filtering, ranking, persistence, and queue exhaustion |
| Source file selection and reading | Controller | Exact paths and offsets, page completion, no model-selected files, no source restart |
| Function and declaration identification | Controller | Indexed declarations, signatures, callsites and provenance |
| Probe syntax and argument construction | Controller | Source-grounded typed arguments and executable probe plans |
| Probe execution | Controller | Execute approved isolated probes, no model tool invocation |
| Probe result recording | Controller | Immutable case IDs, inputs, outputs, errors and provenance |
| Source-to-caller tracing | Controller | Verified caller chain, entry reachability, source-to-sink links |
| Evidence validation | Independent deterministic verifier | Reproduce, check source/impact/authority links and reject unsupported claims |
| Ambiguous vulnerability reasoning | Qwen | Bounded structured semantic question about controller-supplied evidence only; cannot return tools, paths, commands, workflow actions or finalization decisions |
| Final technical assessment | Qwen + independent reviewer | Both assess verified evidence; reviewer independently checks claims and rejects unsupported findings |
| Report construction | Controller | Deterministically assemble only accepted case IDs, evidence and reviewer conclusions |
| Report prose | Qwen | Rewrite controller-assembled report only; cannot add facts, findings, evidence or change disposition |

## Mandatory invariants
1. Model output is never parsed or dispatched as a mechanical workflow action.
2. Controller owns the lifecycle and finalization eligibility, including when no candidate or probe is possible.
3. Source and probe queues work for zero, one, 48, and thousands of files, including decoys, without model fallback.
4. Every rejected candidate is logged with a reason; a finite exhaustion result is not a speculative final answer.
5. Model semantic responses use a separate schema, include evidence references, and are rejected if they contain unverified claims or operational instructions.
6. Independent review runs only after evidence verification and cannot be bypassed.
7. Reports contain no model-invented claims; report prose is checked against assembled facts.
8. Cross-language regression tests cover Solidity, Java, JavaScript, and Python; include 88mph-style small corpus, Level-6-scale corpus, empty corpus, invalid JSON, repeated finalization attempts, source-page progression, and no-probe exhaustion.
9. No gauntlet required as a merge gate unless separately authorized; this does not waive the regression tests above.
10. PR must not be merged until all eleven stages above are implemented and verified.