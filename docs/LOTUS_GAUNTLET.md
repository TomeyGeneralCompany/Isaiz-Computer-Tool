# LOTUS Gauntlet

**Proprietary benchmark infrastructure developed on behalf of Tomey General Company, LLC.**

LOTUS Gauntlet runs the production investigator against large, owned synthetic security repositories. Each challenge contains an intentionally introduced vulnerability, caller relationships, competing candidates, and code that must be navigated before it can be tested.

## Four languages, randomized by default

Gauntlet now generates challenges in **Solidity, Python, JavaScript, and Java**. Each run selects one language at random unless an explicit language override is supplied.

| Language | Synthetic investigation | Reproduction path |
| --- | --- | --- |
| Solidity | Privileged settlement and unprotected operator rotation among guarded decoy contracts | Local EVM, `solidity_sequence` |
| Python | Unescaped user input passing through renderer, pipeline, and codec modules | Isolated `html_reflection` |
| JavaScript | Multi-module CommonJS rendering and unsanitized user input | Isolated `html_reflection` |
| Java | Package-qualified rendering, supporting classes, and unsanitized input | Isolated Java `html_reflection` |

All four languages support five difficulty levels: **12, 28, 48, 84, and 144 source files**. Level 4 (84 source files) is the default.

Random selection chooses among the four languages with equal probability. Each run records the generated seed and selected language in `manifest.json`; providing the same seed reproduces the language selection. The generated source tree is deterministic for that language and level.

The answer key is saved outside the repository being investigated. The model receives only the synthetic program scope and source code.

## Local use

Install the normal application dependencies first, then generate a randomly selected fixture **without running the model**:

```bash
node --import tsx scripts/lotus-gauntlet.ts --prepare --level=4 --output=data/gauntlet/example
```

Run one randomly chosen real-controller benchmark (requires the installed reproduction runtimes and a running local Ollama instance):

```bash
LOCAL_OLLAMA_MODEL=qwen3:4b node --import tsx scripts/lotus-gauntlet.ts --run --level=4 --output=data/gauntlet/attempt-01
```

Reproduce a recorded challenge, or target a single language for debugging:

```bash
node --import tsx scripts/lotus-gauntlet.ts --prepare --level=4 --seed=REPLAY_SEED --output=data/gauntlet/replay
node --import tsx scripts/lotus-gauntlet.ts --prepare --level=4 --language=java --output=data/gauntlet/java
```

The `--language` flag accepts `random`, `solidity`, `python`, `javascript`, or `java`. Use a fresh output directory per run.

## GitHub Actions

The [Gauntlet workflow](../.github/workflows/lotus-gauntlet.yml) is manually triggered. It provides a difficulty selection, a **language** choice (default `random`), an optional replay seed, and two operating modes.

- **Prepare:** installs the Node application dependencies and generates a random synthetic challenge; it does not start Ollama or investigate the code.
- **Run:** installs the reproduction toolchains, starts Qwen3:4b on the four-vCPU CPU-only runner, selects one language, and executes the real production `runLocalProgramHunt` path and independent reviewer.

No recurring, push, or pull-request trigger starts a Gauntlet model run. No external bug-bounty programs are contacted, and no bounty report is submitted.

The workflow stores its logs and result artifacts for 30 days.

## Diagnostics and grading

The run output includes:

- `manifest.json` — chosen language, seed, level, source count, and synthetic Git commit
- `answer-key.private.json` — locally retained hidden reference; excluded from GitHub artifacts
- `result.json` — production hunt result and recorded case IDs
- `review.json` — production independent-review result
- `grade.json` — milestones, counters, and first divergence
- `local-hunt-*.log` and `local-review-*.log` — source inspection, model actions, probes, and reviewer evidence

The grader checks source acquisition, source mapping, navigation, candidate exposure, hypothesis/probe planning, completed reproduction, and independently reviewed findings. These stages are evaluated against the language-specific answer key.

The same production evidence and execution gates remain in force regardless of language. Repeating an identical language/level/seed combination makes controller regressions comparable.

Copyright © 2026 Tomey General Company, LLC. All rights reserved.
