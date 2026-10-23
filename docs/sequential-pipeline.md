# Sequential CPU pipeline

The complete launcher now defaults to one coordinated workflow. It parks the separate Python scan/research worker farm; existing results remain on disk. Discovery can refresh program metadata, but does not launch model work during a hunt.

After initial discovery finishes, each automatic pass:

1. Assesses a fixed snapshot of eligible unassessed programs, one at a time. Existing assessments are reused. An assessment failure is logged and does not prevent the rest of the snapshot from finishing.
2. Recovers pending reproduction/review/submission work from earlier runs.
3. Takes a fixed easiest-first snapshot of assessed eligible programs.
4. Investigates one program, then drains its existing independent replay/review/submission path before advancing. Failures, unsupported work and submission blockers do not strand the rest of the list. Provider responses are polled separately; the workflow does not wait for a payout decision.

Newly discovered programs and failed assessments are considered on the next pass. Stopping Auto Hunt prevents the next program from starting; the active program's review handoff is drained. Stop Analysis during automatic analysis pauses Auto Hunt after the current assessment. Kill All also disables automatic dispatch. Inference and audit timeouts remain bounded.

A separate OS-held workflow lock spans whole stages and program handoffs across the dashboard and orchestrator. Nested calls reuse ownership; process death releases the lock. Dashboard manual jobs queue behind the active pass, rather than competing for model time. The existing inference lock is still used inside each stage.

Difficulty is a conservative metadata estimate (0–100, lower first), using assessed stack fit, source accessibility, scope breadth and source repository count. Unknown rubric fields receive middle values. It is not an AST-derived code complexity measurement and cannot predict whether a vulnerability exists. Payout is only an ascending tie-breaker; an easy high-payout project can precede a difficult low-payout one. The dashboard Auto Hunt queue uses the same ordering as dispatch and shows the estimated difficulty.

Daily quota enforcement and submission eligibility remain intact. A consumed quota does not stop analysis or pending-report recovery. The dashboard and journal show the quota count, limit and UTC reset time when it prevents new hunts. Existing quota files only record a count and day, not historical attempt attribution; no quota is reset by this update.

The complete launcher uses sequential mode by default. `AUTOHACK_SEQUENTIAL_PIPELINE=false` in the launcher environment restores the former concurrent scheduling/worker launch behavior; keep the default for CPU-only use.

Validation: `scripts/test-sequential-pipeline.ts` tests stage order, review after hunt failure, continuation, pause, quota behavior, difficulty sorting and cross-process workflow exclusion. `scripts/test-analysis-scheduling.ts` exercises the actual dashboard queue using temporary SQLite and mock Ollama. Existing source/reproduction and service startup CI checks remain enabled.

## Preparation and inspection recovery

Local automatic hunts check quota availability before preparation, but atomically consume a slot only after source acquisition and capability preflight, immediately before model inspection. Preparation failures and unsupported inventories do not consume a slot. Existing counts are preserved; nonlocal dispatch accounting is unchanged.

Temporary root-clone transport failures get one retry with a fresh checkout. Missing/private repositories, redirects and TLS configuration failures are stored against the exact source scope and excluded from automatic selection until the scope changes or a manual hunt retries acquisition. Other acquisition failures become eligible after 15 minutes. Existing hunt backoff also applies. A changed URL/scope invalidates this cache; successful manual acquisition clears its entry.

A failed submodule download leaves the main checkout available for inspection. Missing dependency paths are included in the audit prompt. Reproduction for that partially acquired repository is conservatively blocked until its dependencies are available. Invalid or escaping submodule manifests still reject acquisition. Programs whose repositories are all unsupported or waiting on acquisition are excluded from automatic selection.

Inspection tracks a bounded navigation queue derived from actual directory results and returned page cursors. Repetition feedback supplies a concrete remaining action. Checkpoints retain bounded navigation hints alongside tool progress; hints never count as evidence.

After reading source, a model may return an empty findings list with `outcome: "no_testable_candidate"` and an explanatory `reason`. This ends the pass with partial coverage, saves its checkpoint and permits the next program to run. It creates no report, does not claim complete coverage and does not increase the verified miss streak. Reported findings still require successful reproduction and source/caller evidence.
