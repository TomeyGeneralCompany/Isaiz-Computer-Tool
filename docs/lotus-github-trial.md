# LOTUS real-world GitHub trial

Workflow: [LOTUS Real-World Trial](../.github/workflows/lotus-real-world-trial.yml)

This is infrastructure only. It has **workflow_dispatch only**: no push, pull_request, cron, or automatic test trigger. The workflow is deliberately not executed by installing it.

## Runner and execution

* Public-repository GitHub-hosted `ubuntu-24.04` runner: 4 vCPUs, 16 GB RAM. CPU-only Qwen3:4b via Ollama.
* Installs existing project and isolated verifier prerequisites with Node 22, Java 21, bubblewrap, Solidity and static analyzers.
* Uses the existing four test stages: source workflow regressions; real Qwen3 controller; real Qwen3 scoped synthetic hunt and review; finally `bash scripts/run-one-bounty.sh --program PROGRAM_ID --timeout-min 35`.
* Uses existing source chunking, dynamic allowances and strict evidence verification. No automatic bounty submission.
* GitHub Actions imposes a six-hour maximum job duration independent of LOTUS's inactivity watchdog.
* Always retains bounded redacted logs as a downloadable Actions artifact (30 days). Optionally mirrors logs to the private `TomeyGeneralCompany/AutoHack-Overnight-Diagnostics` repository under `runs/github-RUN-ATTEMPT`.

## Credentials and real-program data (required before any manual launch)

Add the GitHub Actions **repository secret** `LOTUS_TRIAL_PROGRAM_JSON`. It must be one actual assessed program record from your existing local `data/bounty.db`, with its real program scope and assessment. This ensures the cloud run examines a real authorized target and doesn't fake eligibility. No real provider authentication credentials are stored in this workflow.

From the local LOTUS checkout, export a program record after substituting its exact program ID:

```bash
python3 - <<'PY'
import sqlite3,json
db=sqlite3.connect('data/bounty.db')
db.row_factory=sqlite3.Row
program='YOUR_EXISTING_PROGRAM_ID'
rows=db.execute('SELECT id,provider,provider_program_id,name,url,scope_summary,reward_min_cents,reward_max_cents,response_efficiency,requires_signal FROM security_programs WHERE id=?',(program,)).fetchall()
if len(rows)!=1: raise SystemExit('Expected one existing assessed program')
print(json.dumps(dict(rows[0]),separators=(',',':')))
PY
```

Copy the printed JSON to GitHub > Repository Settings > Secrets and variables > Actions > New repository secret, named `LOTUS_TRIAL_PROGRAM_JSON`. Choose a program still explicitly in scope and eligible. The workflow's manually entered `program_id` must match this saved record. Do not store personal credentials or API tokens in the JSON.

**Optional:** set repository secret `LOTUS_DIAGNOSTICS_TOKEN` to a fine-grained GitHub token with Contents read/write rights to the *private* diagnostics repository. Otherwise, the GitHub Actions artifact still preserves results remotely. This token is not used for bounty submissions.

## Manual activation (later, not as part of infrastructure setup)

Open GitHub > Actions > LOTUS Real-World Trial (manual only) > Run workflow; enter the exact `program_id`. No workflow is scheduled and nothing runs until this button is used.

The GitHub Actions UI shows live logs. After completion, the job's artifact and (when the optional token is configured) private repository logs can be inspected without keeping the laptop online.

## Scope of infrastructure installation

Adding this workflow doesn't create a program record, download Ollama, start an agent, touch the local laptop, or run any tests. Those operations are inside the manual workflow, and run only upon dispatch.
