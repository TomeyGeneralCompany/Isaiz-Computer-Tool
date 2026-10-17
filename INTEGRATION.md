# AutoHack integrated local deployment

The TypeScript orchestrator and the Python offline pipeline are separate processes.
`run-complete-autohack.sh` starts both, using `scripts/run-offline-workers.py`
to supervise the offline workers. **Do not interpret a running process as a
verified vulnerability or a successful bounty submission.**

## Initial setup (Zorin OS / Linux)

From this repository's checkout:

```bash
npm ci
npm run db:push
ollama list
bash run-complete-autohack.sh
```

Node.js 22+, Python 3, Git and a local Ollama installation are expected.
The triage and research defaults use `qwen3:4b`. Some workers require
additional tools: `bwrap` for Python reproduction and Podman or Docker plus
a **preloaded** Foundry image for Solidity research. Workers report blocked
states if those prerequisites are absent; they do not download images or
execute arbitrary host commands.

The dashboard is normally at http://localhost:3456. Worker logs are written
to `data/worker-logs/`. To launch only offline workers:

```bash
python3 -u scripts/run-offline-workers.py
```

To launch only selected workers:

```bash
python3 -u scripts/run-offline-workers.py --only scope investigator triage verification
```

## Boundaries and current limitations

- Scope synchronization imports exact GitHub assets from the Immunefi
  catalog, subject to a time-limited scope cache. Program rules must still
  be checked before active testing or disclosure.
- The Python pipeline performs passive discovery, local static inspection,
  model-assisted triage, offline evidence checking, and **bounded sandboxed**
  reproduction when a compatible local case is available.
- The research engine currently has a Solidity/Foundry adapter. It does not
  provide generalized reproduction for every language or vulnerability.
- An executed test is not automatically a verified security issue. Evidence,
  exploitability, impact, duplicates and current program eligibility require
  independent assessment.
- The Python workers do **not** automatically submit reports or mark their
  candidates verified. The supervised importer transfers eligible triage drafts
  to the shared findings database as **discovered, unverified** candidates only,
  with stable deduplication IDs and an exact Immunefi source-asset match.
  It deliberately does not convert offline leads into validated or report-ready
  findings.
- The TypeScript application has its own discovery, solver, review and
  HackerOne submission implementation. `SECURITY_AUTO_SUBMIT` defaults to
  false. Do not enable it without validating scope, API credentials, report
  quality and the submission gate on your own deployment.

## Check results

GitHub Actions runs Python syntax, offline importer integration tests and TypeScript static checks on each push.
These checks cannot prove that a local Ollama model, container runtime,
credentials, database or platform submission works on your laptop.

## Security hygiene

Never commit `.env`, API tokens, private keys, runtime databases, downloaded
target repositories or generated investigation artifacts. The `.gitignore`
rules prevent *new untracked files* from being added accidentally, but do not
remove anything previously committed or rotate previously exposed credentials.
