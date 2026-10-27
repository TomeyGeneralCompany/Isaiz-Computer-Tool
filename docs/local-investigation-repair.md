# Local investigation controller repair

This change preserves source pagination, the progress-earned turn/time allowance, existing reports and persisted assessments. It does not assert that a small model can discover every vulnerability.

- Every eight source pages (or six other inspections) the production controller requires a probe plan, a specific missing-context question, or an incomplete result. `continue_inspection` records the question, source path and offset, then reopens bounded reading. Identical continuation requests cannot repeat indefinitely.
- Complete bounded probe outputs are retained in pageable `.audit-evidence-*` files for the current pass, so context compaction does not force an identical retest.
- Candidate plans, unanswered questions and recent observations are saved atomically in source-revision-specific `.memory.json` files. They supply navigation on restart, never current evidence or valid case IDs. Report validation still requires current reads and successful reproduction.
- `audit-source-map.json` lists bounded lexical symbol candidates, source offsets, possible callers and probe requirements. It is explicitly incomplete navigation, not compiler binding. Existing Solidity AST readers remain available.
- `audit-static-leads.json` supplies Semgrep/Slither results as unverified leads. Runs are sequential and network-isolated in bubblewrap, use only copied tracked source and repository-owned rules, and never execute project build hooks. Semgrep uses one job. Slither uses an explicit native solc 0.8.30 on one candidate file; incompatible projects remain unsupported. Missing scanners are recorded and do not prevent ordinary source inspection.
- Java preflight now requires a compatible public static String entrypoint rather than assuming any `.java` file can run in the installed probe. A capability-version bump invalidates stale capability exclusions, not saved assessments.
- Production final results may use an actual schema-validated `result` object. Existing `answer` strings remain supported. This removes a requirement to nest escaped JSON inside a string.
- Audit summaries include the configured model profile, whether dynamic allowances were enabled, the extension criteria and recent credited turns.

## Install the optional local tools

`bash scripts/install-static-analysis.sh` installs separate pinned Semgrep and Slither dependencies and solc 0.8.30. It needs network access during installation; scans need no account, cloud service or network. The reproduction-runtime installer also calls it. `LOCAL_STATIC_ANALYSIS=false` disables this extra preprocessing without changing reading/testing.

## Validate on the actual laptop model

Run `node --import tsx scripts/compare-local-model.ts` with the usual application environment loaded and the main service stopped to avoid competing model jobs. Restart the service afterwards. The comparison runs three randomized owned-fixture variants through the **production** controller for each of three profiles, sequentially, with actual isolated Python probes. Results and per-run logs are saved under `data/model-comparisons/`. No settings are changed automatically and no live reports are submitted.

Profiles: `deterministic` (existing temperature-zero default); `qwen` (non-thinking Qwen-recommended sampling); `qwen-planner` (Qwen sampling with thinking in hypothesis/review stages). Thinking and output share the configured output/context budget; CPU threads and context length remain unchanged. Set `LOCAL_MODEL_PROFILE` only after comparing complete, correct results. A pass is evidence for these fixtures, not general investigation success.

A missing result, unsupported probe or exhausted pass must remain incomplete. General Maven/Gradle, browser-dependent JavaScript and arbitrary project test suites are not implemented by these fixed function probes. This repair improves selection and diagnostics rather than misrepresenting them as supported.
