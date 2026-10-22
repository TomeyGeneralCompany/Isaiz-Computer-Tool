# CPU-only review — 22 October 2026

This review covers the supplied overnight screenshots/logs and repository code. The laptop was running the version before PR #16; neither #16 nor this follow-up has been measured on the laptop. It is now switched off. Passing fixtures does not establish that a real bounty will be found or accepted.

## Observed failures

| Evidence | What it establishes |
| --- | --- |
| 05:25 screenshot: no active pipeline, Auto Hunt enabled, 49 queued programs, 20 awaiting analysis | The displayed queue and enabled switch are not proof of active work. The image does not establish why dispatch stopped. |
| Four Instadapp inspection timeouts and one OpenZeppelin timeout | These attempts exhausted their 3,600-second budget without completing inspection. |
| OpenZeppelin socket hangup | A connection ended unexpectedly. The image cannot establish whether Ollama crashed, unloaded a model, or another interruption occurred. |
| Omarchy source-download failure | No authorized source repository was acquired for that attempt. CPU tuning cannot repair missing or inaccessible source. |
| Older Instadapp errors without retained details | Their original causes cannot be recovered from this screenshot. |
| Earlier log: ten reads of the same OpenZeppelin path, each taking roughly 3–7 minutes and generating 37 tokens | Substantial inference time was spent revisiting one file. Old logs do not show offsets, so they do not prove every read was the identical page. |
| Earlier memory snapshot: 1.7 GiB of 2 GiB swap occupied; two model entries, one stopping | Memory pressure/model churn needs measurement. Occupied swap alone does not prove active swapping or explain the timeouts. |

The queue uses the same eligibility function as dispatch. Static-lead work runs before the ordinary queue; solver locks and daily quotas also affect dispatch. The image does not identify which condition applied. Capture `scripts/diagnose-progress.ts` and the orchestrator journal at the time of any recurrence; do not infer a scheduler repair from this screenshot alone.

## Repairs

PR #16 already adds cross-process inference serialization, repeated-page detection with corrective feedback, and per-turn queue/load/prompt/generation timing. Those repairs still need installation on this laptop.

This follow-up:

- Preserves the opening audit messages between turns. Previously the changing progress summary rewrote the second message every time, limiting the reusable prompt prefix. Progress notes now refresh only when history is compacted. This permits cache reuse; the speedup depends on Ollama and other requests.
- Removes a redundant assessment queue outside its deadline. Waiting for the shared inference lock now consumes the caller's timeout, instead of silently adding other assessments' runtimes.
- Aligns the Python research request with the CPU policy: four inference threads, 8,192 context tokens, thinking disabled, and a bounded 1,100-token answer. Its socket timeout is now 600 seconds instead of 100, which was shorter than the observed model turns. Queue waiting remains bounded separately at 600 seconds.
- Rejects incomplete, truncated, oversized, or non-object research responses. These cannot become successful research output.
- Corrects the progress diagnostic's outdated claim that all JavaScript/Solidity reproduction is unsupported.

## Recommended baseline for four cores / eight threads / no GPU

Use four inference threads as the baseline, not eight just because eight logical threads exist. This is a starting point, not a measured optimum. Keep the current 4B audit model while testing these repairs; a larger model would add an unmeasured cost. Keep the 8K audit context because the source/probe instructions need room; shrinking it blindly can break inspection.

Set `OLLAMA_NUM_PARALLEL=1` in the **Ollama server's** environment when installing the update. The repository lock covers this checkout's clients, not unrelated Ollama clients. Do not assume an AutoHack `.env` entry configures a separately managed Ollama service. Ollama documents that parallel requests multiply context memory requirements: https://docs.ollama.com/faq

Do not immediately force `OLLAMA_MAX_LOADED_MODELS=1`: the installation alternates between the assessment and audit models. One resident model may reduce memory use but cause repeated reloads. First compare logged `loadMs` and `queueMs`. Batch assessments before a long hunt if those timings show interference. Model residency is not fixed by request serialization alone.

Measure a short, repeatable owned fixture before another overnight run:

1. Run the existing host verification and model/assessment fixtures after installing the code.
2. Capture per-turn timings, `ollama ps`, and `vmstat 1` during a run. Sustained `si`/`so` indicates active swapping; an old swap allocation alone does not.
3. If model load dominates, investigate residency/model switching. If prompt evaluation dominates, compare the stable-prefix update. If generation dominates, compare three versus four threads on the same fixture. If queue time dominates, reduce competing work.
4. Check temperature and sustained clock speed on the laptop before increasing workload. High CPU use during inference is expected; thermal throttling, active swapping, and lack of useful progress are the problems to measure.

No host performance percentage or bounty-completion guarantee is claimed. Local transaction support remains bounded: solc 0.8.30 and one deployed contract with constructor arguments, transactions and assertions. General multi-contract scenarios and other compiler versions still need separate work.
