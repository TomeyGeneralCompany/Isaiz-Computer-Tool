# LOTUS
### Localized Offensive Testing and Understanding System

**Proprietary Autonomous Security Research Software**  
**Developed on behalf of Tomey General Company, LLC**

LOTUS is an autonomous security research platform developed for the discovery, assessment, and investigation of authorized vulnerability disclosure and bug bounty programs. It integrates locally hosted artificial intelligence, source-code inspection, static analysis, dependency resolution, isolated execution, evidence collection, independent review, and reporting into one investigative system.

LOTUS uses Qwen3 through Ollama for local inference. A structured investigation controller manages source acquisition, reasoning, tool execution, recovery, and persistent evidence. Language-specific execution adapters provide reproduction capabilities across Python, JavaScript, Java, and Solidity.

The platform is designed to operate on conventional Linux hardware without dedicated graphics hardware or paid inference services.

**Copyright © 2026 Tomey General Company, LLC. All rights reserved.**

The LOTUS software and associated materials are proprietary to Tomey General Company, LLC. Public visibility of repository contents does not grant a license to copy, modify, redistribute, or commercially exploit the software.

**Repository:** [TomeyGeneralCompany/Isaiz-Computer-Tool](https://github.com/TomeyGeneralCompany/Isaiz-Computer-Tool)


## Operation

LOTUS follows a unified investigative process:

**Program discovery → Assessment → Source acquisition → Static analysis → Model investigation → Isolated reproduction → Evidence evaluation → Independent review → Reporting**

### Discovery and assessment

LOTUS maintains a SQLite database of programs collected through supported discovery feeds, including HackerOne, Immunefi, and aggregator-supported programs from Bugcrowd, Intigriti, and YesWeHack.

Its selection system evaluates published scope, source-code availability, recorded assessments, reward information, investigation history, and program difficulty. Program assessments persist in `security_programs.scope_summary.assessment`.

### Source acquisition and analysis

LOTUS retrieves repositories identified by eligible program scopes. It indexes source declarations, functions, constructors, callers, and state relationships, then prioritizes candidates using source context and static-analysis leads.

Semgrep and Slither integrations provide additional investigative leads. Source inspection uses bounded pagination and function-level context so large codebases can be investigated with a local model.

### Autonomous investigation controller

The local production path uses **Ollama/Qwen3:4b** and a **LangGraph.js** investigation controller. The controller coordinates source reads, hypotheses, probe specifications, execution, evidence records, and recovery.

Model requests run sequentially. The controller enforces action constraints, preserves investigation state outside the model conversation, and recovers from repeated navigation, incompatible probe plans, empty finals, and invalid model output.

Investigation history records the source ranges inspected, hypotheses considered, probes attempted, observations returned, coverage achieved, and stopping reason.

### Isolated reproduction and dependency resolution

LOTUS executes supported reproduction cases in isolated local environments using language-specific adapters.

| Language | Execution and dependency capabilities |
| --- | --- |
| **Python** | Function execution, input/output observation, and SHA-256-locked pure-Python wheel dependencies |
| **JavaScript** | Exported and asynchronous function probes, with dependency preparation from npm lockfiles |
| **Java** | Text/byte probes, constructor initialization, stateful sequences, interface mocks and proxies, and available project JAR dependencies |
| **Solidity** | Local EVM transaction sequences, contract constructors, state-changing calls, read assertions, npm dependencies, and pinned Foundry submodules |

The shared controller handles investigation progress and evidence requirements; the language adapters implement each runtime's compilation, dependency preparation, and execution mechanics.

### Evidence, review, and reports

LOTUS records test inputs, execution results, source references, and reproduction evidence. The review process evaluates caller reachability, input provenance, execution behavior, impact, and program scope before findings advance through reporting.

Program records, findings, assessments, and investigation history are retained in SQLite and local diagnostic files. The application includes report generation and submission infrastructure. **Automatic bounty submission is disabled by default**; the one-bounty diagnostic runner does not submit reports.

## System requirements

The reference development machine is a Zorin OS/Ubuntu-compatible laptop with an Intel Core i7-8650U (4 cores, 8 threads), 16 GB RAM, and no dedicated GPU.

| Component | Runtime |
| --- | --- |
| Operating system | Ubuntu-compatible Linux, including Zorin OS |
| Application | Node.js 22, npm, TypeScript |
| Model | Ollama, Qwen3:4b |
| Database | SQLite and Drizzle |
| Dashboard | Next.js and tRPC |
| Reproduction | Python 3, Java JDK, Node.js, Solidity local EVM, bubblewrap |
| Service supervision | systemd user service |
| Remote testing | GitHub Actions, CPU-only Ubuntu runner |

The reference configuration is a development system rather than a minimum hardware requirement.

## Installation

Clone the repository:

```bash
git clone https://github.com/TomeyGeneralCompany/Isaiz-Computer-Tool.git
cd Isaiz-Computer-Tool
```

Use Node.js 22 and configure a private `.env` for the installed model and enabled providers. Then run the project's installation and verification entry point:

```bash
bash setup-and-run.sh --verify-only
```

The installer prepares the locked Node dependencies, source-reproduction runtimes, SQLite schema, and host checks. It can import configuration from an existing local installation.

Start the foreground application:

```bash
bash run-complete-autohack.sh
```

The dashboard is available at **http://127.0.0.1:3456**.

For supervised operation:

```bash
bash scripts/install-user-service.sh
bash scripts/control-user-service.sh status
bash scripts/control-user-service.sh logs
```

Service controls include `start`, `stop`, `restart`, `status`, and `logs`. The application uses host locks to prevent competing supervisors and orchestrators from running against the same checkout.

See the [Operator Runbook](docs/OPERATOR_RUNBOOK.md) for configuration, installation, service management, and host diagnostics.

## Single-program investigation

The one-bounty launcher uses the production source investigation and review implementation.

List eligible, assessed programs:

```bash
bash scripts/run-one-bounty.sh --list
```

Investigate a selected program:

```bash
LOCAL_OLLAMA_MODEL=qwen3:4b \
bash scripts/run-one-bounty.sh --program PROGRAM_ID --timeout-min 35
```

Replace `PROGRAM_ID` with an eligible identifier returned by the list command.

This launcher runs one authorized program investigation without starting the recurring scheduler. Its timeout measures **inactivity**, not the total wall-clock duration of productive work. Results are written beneath `data/one-bounty/`, with investigation logs maintained under `data/logs/`.

### Progress-aware model allowances

The default local investigation starts with 80 model turns and a source-inspection budget of 180 minutes. With `LOCAL_HUNT_DYNAMIC_ALLOWANCE=true`, qualifying inspection or reproduction progress can add 40 turns and 60 minutes per extension.

Extension credit comes from newly delivered source ranges and distinct completed probes. The implementation maintains a bounded total turn and time allowance, along with per-request limits and operator cancellation.

### Local model configuration

```dotenv
LOCAL_OLLAMA_MODEL=qwen3:4b
LOCAL_MODEL_ADAPTER=ollama
LOCAL_OLLAMA_TOOL_PROTOCOL=json
LOCAL_HUNT_MAX_TURNS=80
LOCAL_HUNT_NUM_PREDICT=2048
LOCAL_HUNT_DYNAMIC_ALLOWANCE=true
SECURITY_SOURCE_CODE_TIMEOUT_MINUTES=180
```

The local model uses an 8,192-token context by default. Source reads are paginated at up to 2,000 characters and fitted into the available response context. `LOCAL_HUNT_NUM_PREDICT` controls generation length.

`LOCAL_MODEL_ADAPTER=qwen-agent` selects the installed Qwen-Agent transport bridge to the local Ollama endpoint. Tool execution, evidence validation, and stage restrictions remain with the production controller.

## Testing and diagnostics

LOTUS includes regression and integration suites for repository navigation, static-analysis leads, source reproduction, controller transitions, model interaction, evidence validation, program selection, database operations, reporting, and independent review.

Run source workflow regressions:

```bash
npx tsx scripts/test-source-workflow.ts
```

Run the production controller against owned test fixtures using the installed model:

```bash
node --import tsx scripts/test-production-workflow.ts --real-model
```

The source-reproduction suite exercises Python, JavaScript, Java, and Solidity in the isolated runtime. Controller and investigation diagnostics are saved under `data/` for review.

### GitHub-hosted real-world trial

The repository includes the [LOTUS Real-World Trial](.github/workflows/lotus-real-world-trial.yml), a **manually dispatched** GitHub Actions workflow configured for a CPU-only Ubuntu runner with four virtual CPUs and 16 GB RAM.

The remote trial uses the existing four-stage sequence:

1. Source workflow regressions.
2. Real Qwen3 production-controller acceptance.
3. Real Qwen3 scoped synthetic investigation and independent review.
4. One authorized real-program investigation through the production one-bounty launcher.

GitHub Actions retains diagnostic artifacts. With the optional private-repository token, the workflow also mirrors logs into `TomeyGeneralCompany/AutoHack-Overnight-Diagnostics` for remote inspection.

The workflow runs only when manually dispatched. Setup requires an existing assessed program record supplied as a repository secret. Full configuration is documented in the [GitHub Trial Guide](docs/lotus-github-trial.md).

### Investigation records

LOTUS captures model activity, read ranges, completed reproduction steps, errors, evidence identifiers, review results, and stopping reasons. Its logs distinguish ongoing investigation, incomplete coverage, recorded observations, and reviewed findings.

## Architecture

| Component | Responsibility |
| --- | --- |
| **Qwen3 / Ollama** | Locally hosted investigative inference |
| **LangGraph.js controller** | Investigation stages, actions, context, recovery, and evidence state |
| **Source analysis** | Repository acquisition, declarations, callers, static leads, and prioritization |
| **Language adapters** | Isolated Python, JavaScript, Java, and Solidity reproduction |
| **SQLite / Drizzle** | Persistent program, assessment, and finding data |
| **TypeScript / Node.js** | Application orchestration and internal services |
| **Next.js / tRPC** | Dashboard and application interface |
| **GitHub Actions** | Automated regression CI and manually dispatched real-world trials |
| **systemd** | Linux service supervision |

## Development status

LOTUS has implemented local-model investigation, source navigation, static analysis, language-specific reproduction, dependency preparation, evidence recording, independent review, and controller recovery. Development is focused on the performance and reliability of complete autonomous investigations against real eligible programs.

Detailed host setup, acceptance results, and operating procedures are maintained in the [Operator Runbook](docs/OPERATOR_RUNBOOK.md), [Readiness Documentation](AUTONOMOUS_READINESS.md), and [GitHub Trial Guide](docs/lotus-github-trial.md).

---

**LOTUS — Localized Offensive Testing and Understanding System**  
**Tomey General Company, LLC**  
**Copyright © 2026 Tomey General Company, LLC. All rights reserved.**
