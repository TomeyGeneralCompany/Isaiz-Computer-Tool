import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

const commaSplit = z
  .string()
  .transform((s) => (s ? s.split(",").map((x) => x.trim()) : []));

// Literal environment booleans: Boolean("false") is true, so do not use envBoolean.
const envBoolean = z.preprocess(
  (v) => typeof v === "string" ? v.trim().toLowerCase() : v,
  z.union([z.literal("true"), z.literal("false"), z.boolean()])
).transform(v => v === true || v === "true");

const configSchema = z.object({
  // Auth
  GITHUB_TOKEN: z.string().min(1),
  ANTHROPIC_API_KEY: z.string().optional().default(""),

  // Claude backend: "cli" (uses Max subscription) or "api" (uses ANTHROPIC_API_KEY)
  CLAUDE_BACKEND: z.enum(["cli", "api"]).default("cli"),

  // HackerOne
  HACKERONE_ENABLED: envBoolean.default(false),
  HACKERONE_POLL_MINUTES: z.coerce.number().default(60),
  HACKERONE_USERNAME: z.string().optional().default(""),
  HACKERONE_API_TOKEN: z.string().optional().default(""),

  // Immunefi (crypto/web3 bounties — all have source code)
  IMMUNEFI_ENABLED: envBoolean.default(false),

  // Huntr (AI/ML open source bounties — all have source code)
  HUNTR_ENABLED: envBoolean.default(false),

  // Aggregator (bounty-targets-data — discovers programs from Bugcrowd, Intigriti, YesWeHack, Federacy)
  AGGREGATOR_ENABLED: envBoolean.default(false),

  // Security solver
  SECURITY_AUTO_HUNT_ENABLED: envBoolean.default(false),
  SECURITY_HUNT_TIMEOUT_MINUTES: z.coerce.number().default(60),
  SECURITY_SOURCE_CODE_TIMEOUT_MINUTES: z.coerce.number().default(180),
  LOCAL_HUNT_NUM_PREDICT: z.coerce.number().int().min(32).max(4096).default(2048),
  SECURITY_MIN_CONFIDENCE: z.coerce.number().default(0.65),
  SECURITY_MIN_RUBRIC_SCORE: z.coerce.number().default(8), // minimum adversarial review rubric total (out of 15) to pass
  SECURITY_HUNT_COOLDOWN_HOURS: z.coerce.number().default(2),
  SECURITY_MONTHLY_EARNINGS_TARGET_CENTS: z.coerce.number().int().min(0).default(400000), // tracking goal, not a guarantee
  SECURITY_MIN_REWARD_CENTS: z.coerce.number().default(10000), // $100 minimum to justify 2h Opus
  SECURITY_MAX_DAILY_HUNTS: z.coerce.number().default(999), // effectively unlimited
  SECURITY_MAX_REVISE_ATTEMPTS: z.coerce.number().default(2), // deprecated — review is now binary approve/reject
  SECURITY_SUBMISSION_POLL_MINUTES: z.coerce.number().default(60),
  SECURITY_AUTO_SUBMIT: envBoolean.default(false), // auto-submit findings that pass review with "submit" recommendation
  EXCLUDE_SECURITY_PROGRAMS: commaSplit.default([]), // comma-separated program handles to skip (e.g. "okg,spotify")
  SKIP_SIGNAL_REQUIRED: envBoolean.default(true), // hold Signal-required submissions; nonlocal hunts also skip these programs
  SKIP_PREVIOUSLY_HUNTED: envBoolean.default(true), // skip completed hunts; local completion requires recorded coverage
  SKIP_WEB_ONLY_PROGRAMS: envBoolean.default(true), // skip programs without source code in scope

  // Models
  ANALYSIS_MODEL: z.string().default("sonnet"),
  CLAUDE_MODEL: z.string().default("opus"),
  REVIEW_MODEL: z.string().default(""), // model for adversarial review, empty = use CLAUDE_MODEL
  SUBMISSION_MODEL: z.string().default(""), // model for report drafting, empty = use CLAUDE_MODEL

  // Effort levels (low | medium | high)
  HUNT_EFFORT: z.string().default("high"),
  REVIEW_EFFORT: z.string().default("high"),
  SUBMISSION_EFFORT: z.string().default("high"),
  ANALYSIS_EFFORT: z.string().default("high"),

  // Paths
  WORKSPACE_DIR: z.string().default(".workspaces"),
  DB_PATH: z.string().default("data/bounty.db"),

  // Dashboard
  DASHBOARD_PORT: z.coerce.number().default(3456),
});

export type Config = z.infer<typeof configSchema>;

let _config: Config | null = null;

// Runtime overrides that can be changed without restart (e.g. from dashboard).
// Persisted to a shared JSON file so both the orchestrator and dashboard processes see them.
const _runtimeOverrides: Partial<Config> = {};

const OVERRIDES_FILE = join(process.env.PROJECT_ROOT || process.cwd(), "data", "runtime-overrides.json");
let _fileOverridesCache: { data: Partial<Config>; readAt: number } | null = null;
const FILE_CACHE_TTL_MS = 2000;

function parseOverrides(raw: Record<string, unknown>): Partial<Config> {
  const validated = configSchema.partial().strict().parse(raw);
  // Zod 4 applies nested defaults inside partial objects. Overrides must contain
  // only explicitly provided keys, otherwise defaults overwrite environment values.
  return Object.fromEntries(Object.keys(raw).map(key => [key, validated[key as keyof Config]]));
}

function readFileOverrides(): Partial<Config> {
  const now = Date.now();
  if (_fileOverridesCache && now - _fileOverridesCache.readAt < FILE_CACHE_TTL_MS) {
    return _fileOverridesCache.data;
  }
  try {
    const raw = readFileSync(OVERRIDES_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Runtime overrides must be a JSON object");
    }
    // Reject unknown keys and invalid values rather than trusting a stale or
    // hand-edited JSON file to bypass configuration safety defaults.
    const validated = parseOverrides(parsed);
    _fileOverridesCache = { data: validated, readAt: now };
    return validated;
  } catch {
    _fileOverridesCache = { data: {}, readAt: now };
    return {};
  }
}

export function loadConfig(): Config {
  if (_config) return _config;
  _config = configSchema.parse(process.env);
  return _config;
}

export function getConfig(): Config {
  const base = _config ?? loadConfig();
  const fileOverrides = readFileOverrides();
  return { ...base, ...fileOverrides, ..._runtimeOverrides };
}

/** Set a runtime override that takes effect immediately without restart.
 *  Persisted to disk so other processes (orchestrator ↔ dashboard) see it too. */
export function setRuntimeOverride<K extends keyof Config>(
  key: K,
  value: Config[K],
): void {
  // Validate before changing the live process state.
  const validated = parseOverrides({
    ...readFileOverrides(),
    [key]: value,
  });
  // Persist to shared file for cross-process visibility
  try {
    mkdirSync(join(process.env.PROJECT_ROOT || process.cwd(), "data"), { recursive: true });
    const tempFile = OVERRIDES_FILE + "." + process.pid + ".tmp";
    writeFileSync(tempFile, JSON.stringify(validated, null, 2), { mode: 0o600 });
    renameSync(tempFile, OVERRIDES_FILE);
    _fileOverridesCache = { data: validated, readAt: Date.now() };
    _runtimeOverrides[key] = validated[key] as Config[K];
  } catch (err) {
    throw new Error("Failed to persist runtime override", { cause: err });
  }
}

/** Get current runtime overrides (for dashboard display). */
export function getRuntimeOverrides(): Partial<Config> {
  return { ...readFileOverrides(), ..._runtimeOverrides };
}
