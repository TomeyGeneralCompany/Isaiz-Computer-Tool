# LOTUS Gauntlet

**Proprietary benchmark infrastructure developed on behalf of Tomey General Company, LLC.**

LOTUS Gauntlet places the existing production investigator against a large, owned, synthetic security-research repository. Its purpose is to identify where autonomous investigation diverges from the steps needed to reproduce a deliberately planted vulnerability.

## What is included

- Executable harness: scripts/lotus-gauntlet.ts
- Manually dispatched runner: .github/workflows/lotus-gauntlet.yml
- Five difficulty levels: 12, 28, 48, 84, or 144 Solidity source files
- Level 4 default: 84 files with a privileged settlement path, additional imported library code, caller relationships, and many misleadingly similar authorized methods
- Separate hidden answer key, outside the source repository presented to the investigator
- Real runLocalProgramHunt production path: acquisition, indexing, static leads, Qwen3 controller, isolated reproduction, evidence handling
- Diagnostic results: manifest.json, result.json, grade.json, and original model/audit logs

The challenge presents a settlement application with a reproducible operator-authorization defect. Model instructions do not include the vulnerability location, expected reproduction, or answer key.

## Preparing a challenge without executing any model

From the repository root, after installing application dependencies:

    node --import tsx scripts/lotus-gauntlet.ts --prepare --level=4 --output=data/gauntlet/example

This only creates the synthetic repository, its local git commit, a private answer key, and a manifest.

## Running a real benchmark

After installing the normal isolated reproduction environment and starting local Ollama:

    LOCAL_OLLAMA_MODEL=qwen3:4b node --import tsx scripts/lotus-gauntlet.ts --run --level=4 --output=data/gauntlet/first-attempt

This invokes the real investigation controller through runLocalProgramHunt. A local git shim substitutes the owned challenge at the acquisition boundary, following the existing real-program-hunt acceptance pattern. The model receives only the owned source and the synthetic program's scope.

Each attempt needs a fresh output directory. The generated answer-key.private.json is outside the checked-out fixture and is not uploaded in GitHub diagnostic artifacts.

## GitHub Actions

[LOTUS Gauntlet (manual only)](../.github/workflows/lotus-gauntlet.yml) has no push, pull_request, or schedule trigger.

Select a difficulty level and one of two modes:

- prepare — generate a synthetic repository and manifest without starting Ollama or conducting an investigation
- run — install the normal runtimes, start CPU-only Qwen3:4b, and run the actual production investigation

The GitHub runner uses ubuntu-24.04 with four virtual CPUs and 16 GB RAM. The job is bounded by the GitHub Actions duration limit and retains logs as downloadable artifacts for 30 days. No live bounty target is contacted and no bounty submission occurs.

The workflow is not triggered by merging its code. Only manual dispatch starts a benchmark.

## Interpreting grade.json

The grader records sequential milestones:

1. Source acquisition
2. Source map construction
3. Source navigation
4. Relevant candidate exposure
5. Relevant method analysis
6. Probe planning
7. Probe execution
8. Finding/review readiness

The first absent milestone becomes firstDivergence. Counters include rejected workflow actions, premature finals, source-handoff recovery, completed probes, and allowance extensions.

The grader is an aid for investigation analysis. Source-name presence in a transcript alone does not prove the model understood the implementation; the original log, reproduced case IDs, and final evidence determine the complete outcome. Repeating the same challenge with unchanged source allows direct comparison of two controller revisions.

## Extension plan

The first implemented challenge is Solidity, modeled on the investigation difficulties encountered with large on-chain codebases. The harness is designed to support additional controlled repositories using the same production entry point, including Java projects with dependencies, Python package graphs, and multi-module JavaScript programs.

Copyright © 2026 Tomey General Company, LLC. All rights reserved.
