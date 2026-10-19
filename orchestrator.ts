import "dotenv/config";
// Defaults follow dotenv so the operator's selected model is honored.
process.env.LOCAL_OLLAMA_MODEL ??= "qwen3:4b";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

// Set PROJECT_ROOT so all packages resolve paths correctly
const __filename = fileURLToPath(import.meta.url);
process.env.PROJECT_ROOT ||= dirname(__filename);

import { join } from "node:path";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import cron from "node-cron";
import { loadConfig, getConfig, createLogger, claimDailyHuntSlot } from "@bounty/core";
import { pollHackerOne, pollImmunefi, pollHuntr, pollAggregator, pollSubmissionStatuses, backfillSignalRequirements } from "@bounty/security-discovery";
import { processSecurityProgramQueue } from "@bounty/security-analyzer";
import {
  huntProgram,
  processStaticLeadQueue,
  pickBestProgram,
  readSecuritySolverStatus,
  clearSecuritySolverStatus as clearSecurityStatus,
  clearAdversarialReviewStatus,
  forceStopSecuritySolver,
  processAdversarialQueue,
} from "@bounty/security-solver";

const log = createLogger("orchestrator");

// Node-cron minute fields range from 0 to 59. An interval of 60 minutes
// must be represented as an hourly schedule, not "*/60 * * * *".
function pollSchedule(minutes: number): string {
  if (!Number.isSafeInteger(minutes) || minutes < 1) {
    throw new Error(`Invalid polling interval: ${minutes}`);
  }
  if (minutes < 60) return `*/${minutes} * * * *`;
  if (minutes % 60 === 0 && minutes / 60 < 24) {
    return `0 */${minutes / 60} * * *`;
  }
  if (minutes === 1440) return "0 0 * * *";
  throw new Error(`Polling interval ${minutes} minutes cannot be expressed reliably as a cron schedule`);
}

function startDashboard(port: number) {
  const require = createRequire(import.meta.url);
  const child = spawn(process.execPath, [require.resolve("next/dist/bin/next"), "dev", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: fileURLToPath(new URL("./packages/dashboard", import.meta.url)),
    env: { ...process.env },
    // Own Next's descendants as a group. Streaming avoids execFile's output
    // buffer limit killing a healthy long-running dashboard after enough logs.
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (d: Buffer) => process.stdout.write(d));
  child.stderr?.on("data", (d: Buffer) => process.stderr.write(d));
  child.on("error", (err) => log.error({ err }, "Dashboard failed to start"));
  log.info({ port }, "Dashboard starting");
  return child;
}

function main() {
  const config = loadConfig();
  let shuttingDown = false;

  log.info(
    {
      claudeModel: config.CLAUDE_MODEL,
      hackeroneEnabled: config.HACKERONE_ENABLED,
      autoHuntEnabled: config.SECURITY_AUTO_HUNT_ENABLED,
    },
    "Starting Security Bounty Hunter",
  );

  // Clear stale solver status files from previous run
  clearSecurityStatus().catch(() => {});
  clearAdversarialReviewStatus().catch(() => {});

  // Hunt-lock recovery is serialized by the solver whenever a job acquires it.

  // Security analysis runs after HackerOne discovery to assess programs
  let securityAnalysisRunning = false;
  let assessmentRevision = 0;
  function runSecurityAnalysisQueue() {
    if (securityAnalysisRunning) return;
    securityAnalysisRunning = true;
    processSecurityProgramQueue({onProgramAssessed:() => {assessmentRevision++;}})
      .catch((err) => log.error({ err }, "Security program analysis queue error"))
      .finally(() => { securityAnalysisRunning = false; });
  }

  // HackerOne discovery polling
  if (config.HACKERONE_ENABLED) {
    cron.schedule(pollSchedule(config.HACKERONE_POLL_MINUTES), async () => {
      try {
        await pollHackerOne();
        await backfillSignalRequirements();
        runSecurityAnalysisQueue();
      } catch (err) {
        log.error({ err }, "HackerOne poll error");
      }
    });
    log.info({ minutes: config.HACKERONE_POLL_MINUTES }, "Scheduled HackerOne poll");
  } else {
    log.info("HackerOne disabled, skipping cron");
  }

  // Immunefi discovery polling (crypto/web3 bounties with source code)
  if (config.IMMUNEFI_ENABLED) {
    cron.schedule(pollSchedule(config.HACKERONE_POLL_MINUTES), async () => {
      try {
        await pollImmunefi();
        runSecurityAnalysisQueue();
      } catch (err) {
        log.error({ err }, "Immunefi poll error");
      }
    });
    log.info("Scheduled Immunefi poll");
  }

  // Huntr discovery polling (AI/ML open source bounties)
  if (config.HUNTR_ENABLED) {
    cron.schedule(pollSchedule(config.HACKERONE_POLL_MINUTES), async () => {
      try {
        await pollHuntr();
        runSecurityAnalysisQueue();
      } catch (err) {
        log.error({ err }, "Huntr poll error");
      }
    });
    log.info("Scheduled Huntr poll");
  }

  // Aggregator discovery polling (Bugcrowd, Intigriti, YesWeHack, Federacy — source code only)
  if (config.AGGREGATOR_ENABLED) {
    cron.schedule(pollSchedule(config.HACKERONE_POLL_MINUTES), async () => {
      try {
        await pollAggregator();
        runSecurityAnalysisQueue();
      } catch (err) {
        log.error({ err }, "Aggregator poll error");
      }
    });
    log.info("Scheduled aggregator poll");
  }

  // Allow operator pause to interrupt long idle waits promptly.
  async function waitWhileEnabled(ms: number, wakeForAssessment = false) {
    const initialRevision = assessmentRevision;
    for (let waited = 0; waited < ms; waited += 1000) {
      if (shuttingDown || !getConfig().SECURITY_AUTO_HUNT_ENABLED || (wakeForAssessment && initialRevision !== assessmentRevision)) return;
      await new Promise<void>(resolve => setTimeout(resolve, Math.min(1000, ms - waited)));
    }
  }

  // Security auto-hunt: triggers immediately after previous hunt's evaluation pipeline completes
  let autoHuntScheduled = false;

  async function runAutoHuntLoop() {
    if (autoHuntScheduled) return;
    autoHuntScheduled = true;
    try {
      while (!shuttingDown) {
        const currentConfig = getConfig();
        if (!currentConfig.SECURITY_AUTO_HUNT_ENABLED) break;

        if (await processStaticLeadQueue()) {
          await processAdversarialQueue();
          await waitWhileEnabled(5000);
          continue;
        }

        const program = pickBestProgram();
        if (!program) {
          log.info("No eligible programs for auto-hunt — waiting 5 min for assessments/cooldowns");
          await waitWhileEnabled(5 * 60 * 1000,true);
          continue;
        }

        // Persist dispatch count before launching; crashes also consume quota.
        try {
          if (!claimDailyHuntSlot(currentConfig.SECURITY_MAX_DAILY_HUNTS)) {
            log.info("Daily dispatch limit reached; waiting for next UTC day");
            await waitWhileEnabled(60 * 1000);
            continue;
          }
        } catch (error) {
          log.error({ error }, "Daily quota unavailable; refusing unsafe dispatch");
          await waitWhileEnabled(60 * 1000);
          continue;
        }

        log.info({ name: program.name, programId: program.id }, "Auto-launching security hunt");
        try {
          await huntProgram(program, "auto");
        } catch (err: any) {
          if (err.message?.includes("already busy")) {
            log.info("Solver busy — waiting 2 min before retrying");
            await waitWhileEnabled(2 * 60 * 1000);
            continue;
          }
          log.error({ err, programId: program.id }, "Security hunt error — backing off");
          await waitWhileEnabled(60 * 1000);
          continue;
        }

        // Run adversarial review on report_ready findings from this hunt
        try {
          await processAdversarialQueue(process.env.LOCAL_OLLAMA_MODEL ? undefined : program.id);
        } catch (err) {
          log.error({ err }, "Post-hunt adversarial review error");
        }

        // Prevent immediate tight loops when hunts return unusually quickly.
        await waitWhileEnabled(5000);
      }
    } finally {
      autoHuntScheduled = false;
    }
  }

  cron.schedule("*/1 * * * *",runSecurityAnalysisQueue);

  // Resume report work even if its program will not receive another hunt.
  // This also recovers confirmations from the durable submission outbox.
  let reviewRecoveryRunning = false;
  function recoverPendingReviews() {
    if (shuttingDown || reviewRecoveryRunning) return;
    const settings = getConfig();
    if (!settings.SECURITY_AUTO_HUNT_ENABLED && !settings.SECURITY_AUTO_SUBMIT) return;
    reviewRecoveryRunning = true;
    processAdversarialQueue()
      .catch(error => log.error({error}, "Pending review recovery interrupted"))
      .finally(() => { reviewRecoveryRunning = false; });
  }
  if (process.env.LOCAL_OLLAMA_MODEL) {
    cron.schedule("*/1 * * * *", recoverPendingReviews);
    recoverPendingReviews();
  }

  // Check every 1 minute if auto-hunt should start (lightweight config check)
  cron.schedule("*/1 * * * *", () => {
    try {
      const currentConfig = getConfig();
      if (!currentConfig.SECURITY_AUTO_HUNT_ENABLED) return;
      runAutoHuntLoop().catch((err) => log.error({ err }, "Auto-hunt loop error"));
    } catch (err) {
      log.error({ err }, "Auto-hunt cron config read error");
    }
  });

  // Security submission status poller: check HackerOne for triager decisions
  cron.schedule(pollSchedule(config.SECURITY_SUBMISSION_POLL_MINUTES), async () => {
    if (!config.HACKERONE_ENABLED) return;
    try {
      const updated = await pollSubmissionStatuses();
      if (updated > 0) {
        log.info({ updated }, "Submission statuses updated from HackerOne");
      }
    } catch (err) {
      log.error({ err }, "Submission status poll error");
    }
  });

  // Start dashboard
  const dashboard = startDashboard(config.DASHBOARD_PORT);

  // Run initial discovery for all enabled providers
  const initialPolls: Promise<void>[] = [];
  if (config.HACKERONE_ENABLED) {
    initialPolls.push(
      pollHackerOne()
        .then(() => { runSecurityAnalysisQueue(); })
        .catch((err) => log.error({ err }, "Initial HackerOne poll failed")),
    );
  }
  if (config.IMMUNEFI_ENABLED) {
    initialPolls.push(
      pollImmunefi()
        .then(() => { runSecurityAnalysisQueue(); })
        .catch((err) => log.error({ err }, "Initial Immunefi poll failed")),
    );
  }
  if (config.HUNTR_ENABLED) {
    initialPolls.push(
      pollHuntr()
        .then(() => { runSecurityAnalysisQueue(); })
        .catch((err) => log.error({ err }, "Initial Huntr poll failed")),
    );
  }
  if (config.AGGREGATOR_ENABLED) {
    initialPolls.push(
      pollAggregator()
        .then(() => { runSecurityAnalysisQueue(); })
        .catch((err) => log.error({ err }, "Initial aggregator poll failed")),
    );
  }

  log.info(
    { dashboard: `http://localhost:${config.DASHBOARD_PORT}` },
    "All cron jobs scheduled. Bot is running.",
  );

  // Graceful shutdown
  const shutdown = (exitCode = 0) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info("Shutting down...");
    cron.getTasks().forEach((task) => task.stop());
    const signalDashboard = (signal: NodeJS.Signals) => {
      try {
        if (process.platform !== "win32" && dashboard.pid) process.kill(-dashboard.pid, signal);
        else dashboard.kill(signal);
      } catch (err: any) {
        if (err.code !== "ESRCH") log.error({ err }, "Dashboard shutdown failed");
      }
    };
    signalDashboard("SIGTERM");
    // Allow all Next descendants to finish; bound shutdown even if a child
    // ignores SIGTERM. The complete launcher/systemd can then restart cleanly.
    setTimeout(() => {
      signalDashboard("SIGKILL");
      process.exit(exitCode);
    }, 5000);
  };

  dashboard.on("exit", (code, signal) => {
    if (!shuttingDown) {
      log.error({ code, signal }, "Dashboard exited unexpectedly; restarting the service is required");
      shutdown(1);
    }
  });
  dashboard.on("error", () => shutdown(1));
  process.on("SIGINT", () => shutdown());
  process.on("SIGTERM", () => shutdown());
}

// Catch stray promises so they don't silently disappear
process.on("unhandledRejection", (reason) => {
  const log = createLogger("orchestrator");
  log.error({ reason }, "Unhandled promise rejection");
});

// Uncaught exceptions leave Node in an undefined state — log and exit.
// Use a process manager (pm2, systemd, Docker) to auto-restart.
process.on("uncaughtException", (err) => {
  const log = createLogger("orchestrator");
  log.error({ err }, "Uncaught exception — shutting down");
  process.exit(1);
});

main();
