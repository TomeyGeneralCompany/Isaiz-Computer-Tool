# One-bounty diagnostic (foreground)

This runs the **installed AutoHack engine**, not the old Claude-only `hunt-local.ts`
or a synthetic mocked result. It selects exactly one currently eligible, already
assessed bounty program from the existing SQLite catalog, performs that program's
source investigation with the configured local Ollama model, and drains its normal
independent review queue. It does **not** start program discovery, the dashboard
scheduler, or another program.

## Update an existing Linux checkout

Use the path to your **current checkout**; the usual installation is
`/home/izy/isaiz-bugbounty/autohack-complete`. The commands deliberately do not reset local Git
changes or overwrite `.env`.

```bash
cd /home/izy/isaiz-bugbounty/autohack-complete
systemctl --user stop autohack.service  # only if installed; no-op if absent
git switch main
git pull --ff-only origin main
bash setup-and-run.sh --verify-only
```

Installation verification will not launch a hunt. It checks the host, local model
and account setup. If a command fails, resolve the error before running a bounty.

## Pick and investigate exactly one program

```bash
bash scripts/run-one-bounty.sh --list
bash scripts/run-one-bounty.sh --timeout-min 35
```

The second command chooses the **first eligible** program under the same selection
logic as the regular Auto Hunt scheduler. To choose the exact listed program:

```bash
bash scripts/run-one-bounty.sh --program 'PROGRAM_ID' --timeout-min 35
```

Only exact listed program IDs, handles or names are accepted. Programs with no
assessment, no explicit eligible source scope, or other selection blockers are not
silently forced into scope. Run `--list` to see whether the saved catalog
contains an eligible candidate; an empty list prints selection exclusions.

This command uses `LOCAL_OLLAMA_MODEL` when set, or the application's
`qwen3:4b` research default when it is not. It requires the existing configured
database, Ollama server, and language reproduction prerequisites. The diagnostic
process disables automatic submission regardless of the saved dashboard override. It does **not** change saved configuration or
submit reports. Eligible findings stay in the normal review/report system for
operator inspection.

## Observe and stop

The command prints the chosen program, then writes a dated terminal transcript
and a JSON outcome summary under `data/one-bounty/`. Normal hunt logs remain
under `data/logs/`. It uses the normal source acquisition and reproduction
evidence store. Failure and incomplete coverage are explicitly recorded and are
not treated as vulnerabilities.

Run in the foreground; use Ctrl+C to request cancellation. `--timeout-min 35`
now means **35 minutes without fresh source, analyzer, model, or probe activity**,
not 35 minutes of total run time. An active program can run longer; it is still
only one program, with no next-program dispatch. Source acquisition, static analysis,
model inference and reproduction stages are logged to the terminal as they start
and complete. A status heartbeat shows the current stage and latest recorded
activity every 15 seconds. If there is no new activity for the configured
inactivity interval, the run is cancelled and the summary reports a stall.
An active run has no new arbitrary wall-clock cutoff from this launcher.

The script takes both supervisor/orchestrator file locks, so the regular AutoHack
service must be stopped first. It neither deletes the database nor resets daily
quota, history, existing findings, or outbox. Restart the service separately only
when you're ready to resume automatic operation:

```bash
systemctl --user start autohack.service
```

A zero-finding result on a single source program is not a claim that the entire
program is secure. This test specifically checks whether **one real program**
can pass through the normal investigator and review process without an overnight
batch.
