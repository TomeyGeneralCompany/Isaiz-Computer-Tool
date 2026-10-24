# autohack

**Operational status (2026-10-18):** The local model and complete live bounty workflow are **not yet verified end-to-end**. See [operator setup, verified cash accounting, safety controls and acceptance gates](docs/OPERATOR_RUNBOOK.md) and [readiness evidence](AUTONOMOUS_READINESS.md). The CI fixture only tests an owned synthetic target with an intercepted submission backend; it is not live-provider proof.

autohack is an autonomous security researcher for authorized bug bounty programs. It discovers programs, runs Claude sessions to hunt for vulnerabilities inside each program's declared scope, checks its own findings with a second adversarial model, drafts platform-ready reports, and submits behind a human approval gate.

![autohack dashboard overview](docs/screenshots/dashboard-overview.png)

![autohack dashboard findings pipeline](docs/screenshots/findings.png)

<sub>The real-time tRPC dashboard. Top: the per-stage model control (Scout / Hunt / Review / Submit, each assignable to Opus, Sonnet, or Haiku) and the live pipeline. Bottom: findings moving through their lifecycle with per-finding confidence and status. <b>Shown with sample data.</b></sub>

## How it works

- Discovery polls HackerOne, Immunefi, and Huntr directly, plus an aggregator feed that adds Bugcrowd, Intigriti, YesWeHack, and Federacy. It deduplicates targets and scores each program for opportunity.
- Each hunt spawns Claude in a pseudo-terminal for a 60-minute session scoped to one program's rules. Every tool call streams live to the dashboard over xterm.js.
- A second Claude instance reviews each finding as an adversary, scoring it 0-15 across five dimensions (exploitability, impact, evidence, novelty, scope fit). Anything under 8/15 is rejected before it becomes a report.
- Approved findings get a platform-formatted report with reproduction steps, impact, and remediation, then a separate Sonnet pass trims verbose ones. Submission runs through a manual approval gate; auto-submit is off by default and only applies to findings the reviewer marks "submit".
- Every hunt writes findings, near-misses, and dead ends to a store, so later hunts on the same program start with that history and skip known dead ends.
- Each stage (Scout, Hunt, Review, Submit) runs on Opus, Sonnet, or Haiku, set live from the dashboard. Ephemeral prompt caching cuts repeated input tokens about 90%. Two backends: Claude Max via CLI, or the API via SDK (`CLAUDE_BACKEND=cli|api`).

Built on direct Anthropic SDK calls, no framework wrappers. TypeScript, Next.js 15, tRPC, SQLite with Drizzle, xterm.js, Pino, node-cron.

## Running locally

```bash
npm install
cp .env.example .env    # add your Claude backend and platform tokens
npm run dev             # orchestrator + dashboard on :3456
npm run dashboard       # dashboard only, on :3456
```

## Scope

autohack only hunts targets with active, in-scope bug bounty programs, and never touches systems without authorization. The prompt scaffolding and per-program cheat sheet bound each session to that program's declared scope. Nothing is submitted without passing the approval gate unless auto-submit is explicitly turned on.


### Local source inspection settings

Local source inspection defaults to 180 minutes and 2,048 generated tokens per response.
`LOCAL_HUNT_NUM_PREDICT` accepts 32–4,096; truncated JSON may retry up to 4,096
when context permits. The context remains 8,192 tokens and generation stays sequential.
These are local Ollama settings; they do not select a paid service. Existing environment
or persisted timeout overrides remain in effect. The dashboard timeout now edits the
source-inspection budget when a local model is active.

Run `bash scripts/install-reproduction-runtime.sh` with Node 22 selected to install/check
Python, Node, the Solidity compiler/local EVM, bubblewrap and a Java JDK. Java probes
support public static `Class.method(String)` returning `String`, with JDK or repository
source dependencies. They compile inside the offline sandbox with annotation processing
disabled; Maven/Gradle builds and third-party Java dependencies are not supported.
JavaScript supports exported functions (including async). Solidity uses the installed
0.8.30 compiler and supports the existing string probes and declarative transaction tests.
Source readers and searches work independently of whether a supported test can run.
