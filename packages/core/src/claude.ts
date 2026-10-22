import { postOllamaJson } from "./ollama-http";
import { spawn } from "node:child_process";
import { getConfig } from "./config";
import { extractJsonWithKey } from "./json-utils";
import { createLogger } from "./logger";

const log = createLogger("claude");

interface RunClaudeOpts {
  timeoutMs?: number;
  model?: string;
  maxTokens?: number;
  temperature?: number;
  /** When true, omit --dangerously-skip-permissions so Claude runs tool-free (pure text generation). */
  disableTools?: boolean;
  /** System prompt passed via --system-prompt flag (separate from the user message). */
  systemPrompt?: string;
}

interface StructuredOutputOpts extends RunClaudeOpts {
  /** Tool name for the structured output call. */
  toolName: string;
  /** JSON Schema for the expected output. */
  inputSchema: Record<string, unknown>;
  /** Key to look for when falling back to text extraction (CLI mode). */
  fallbackKey: string;
}

/** Map short model names to full API model identifiers. */
function resolveApiModel(name: string): string {
  const map: Record<string, string> = {
    opus: "claude-opus-4-20250514",
    sonnet: "claude-sonnet-4-20250514",
    haiku: "claude-haiku-4-5-20251001",
  };
  return map[name.toLowerCase()] ?? name;
}

/**
 * Run a prompt through Claude, dispatching to CLI or API based on CLAUDE_BACKEND config.
 * Default: CLI (uses Max subscription, no API cost).
 * Fallback: API (uses ANTHROPIC_API_KEY, pay-per-credit).
 */
export async function runClaude(
  prompt: string,
  opts?: RunClaudeOpts,
): Promise<string> {
  const config = getConfig();

  if (config.CLAUDE_BACKEND === "api") {
    return runClaudeAPI(prompt, opts);
  }

  if (process.env.OLLAMA_DISCOVERY_DIRECT === "true") return runLocalOllama(prompt, opts);
  return runClaudeCLI(prompt, opts);
}

// The shared inference gate serializes requests across processes.
// Start the deadline before acquiring it, so queue time is bounded too.
async function runLocalOllama(
  prompt: string,
  opts?: RunClaudeOpts,
  schema?: Record<string, unknown>,
): Promise<string> {
    const timeoutMs = opts?.timeoutMs ?? Number(process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS || 600000);
    const limit = Number(process.env.OLLAMA_PROMPT_CHARS || 5800);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1800000 ||
        !Number.isSafeInteger(limit) || limit < 3000 || limit > 24000) {
      throw new Error("Invalid Ollama assessment timeout or prompt limit");
    }
    const requestedTokens = opts?.maxTokens ?? (schema ? 1024 : 256);
    if (!Number.isSafeInteger(requestedTokens) || requestedTokens < 1 || requestedTokens > 8192) {
      throw new Error("Ollama assessment maxTokens must be between 1 and 8192");
    }
    const endpoint = new URL(process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat");
    if (!["http:", "https:"].includes(endpoint.protocol) || endpoint.username || endpoint.password ||
        endpoint.search || endpoint.hash || !endpoint.pathname.endsWith("/api/chat")) {
      throw new Error("Invalid Ollama chat endpoint");
    }
    const model = process.env.OLLAMA_MODEL || process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b";
    const bounded = prompt.length > limit
      ? prompt.slice(0, 2400) + "\n[Additional program text omitted]\n" + prompt.slice(-(limit - 2500))
      : prompt;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // A single retry shares the deadline. Never repair or accept partial JSON.
      for (let attempt = 0, tokens = requestedTokens; attempt < 2; attempt++, tokens = Math.min(tokens * 2, 8192)) {
        log.info({model, attempt:attempt + 1, generationLimit:tokens, timeoutMs}, "Ollama assessment started");
        const result = await postOllamaJson(endpoint, {
            model, stream:false, think:false,
            ...(schema ? {format:schema} : {}),
            keep_alive:"10m",
            messages: [
              {role:"system", content:schema
                ? "Return one complete JSON object matching the provided schema. Use concise strings, at most five targets, no markdown or reasoning. /no_think"
                : "Answer concisely, without reasoning traces. /no_think"},
              ...(opts?.systemPrompt ? [{role:"system",content:opts.systemPrompt.slice(0,1200)}] : []),
              {role:"user",content:bounded + (schema ? "\nRespond with JSON only. /no_think" : "")},
            ],
            options:{num_ctx:Math.max(4096,tokens + 2048),num_predict:tokens,temperature:opts?.temperature ?? 0,num_thread:4},
          }, controller.signal, "Ollama assessment") as {
          message?:{content?:string}; done?:boolean; done_reason?:string;
          error?:unknown; eval_count?:number;
        };
        if (result.error) throw new Error("Ollama assessment server error");
        log.info({model, attempt:attempt + 1, reason:result.done_reason, generatedTokens:result.eval_count}, "Ollama assessment response received");
        if (result.done_reason === "length") {
          if (schema && attempt === 0 && tokens < 8192) continue;
          throw new Error("Ollama assessment exhausted its output token budget");
        }
        if (result.done !== true) throw new Error("Ollama assessment response incomplete");
        const output = result.message?.content;
        if (typeof output !== "string" || !output.trim()) throw new Error("Ollama assessment returned no content");
        if (schema) {
          let parsed: unknown;
          try {parsed = JSON.parse(output);} catch {throw new Error("Ollama assessment returned invalid JSON");}
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Ollama assessment did not return a JSON object");
          }
          const required = schema.required;
          if (Array.isArray(required) && required.some(key => typeof key !== "string" || !Object.hasOwn(parsed, key))) {
            throw new Error("Ollama assessment omitted required fields");
          }
        }
        return output.trim();
      }
      throw new Error("Ollama assessment did not complete");
    } catch (error) {
      if (controller.signal.aborted) throw new Error(`Ollama assessment exceeded ${timeoutMs}ms`);
      throw error;
    } finally {clearTimeout(timer);}
}

function runClaudeCLI(
  prompt: string,
  opts?: RunClaudeOpts,
): Promise<string> {
  const config = getConfig();
  const timeoutMs = opts?.timeoutMs ?? 180_000; // 3 minutes default for CLI
  const model = opts?.model ?? config.CLAUDE_MODEL;
  const claudePath = process.env.CLAUDE_PATH || "claude";

  if (opts?.temperature != null) {
    log.debug({ model, temperature: opts.temperature }, "Running Claude via CLI (Max subscription) — CLI does not support --temperature, output may be non-deterministic");
  } else {
    log.debug({ model }, "Running Claude via CLI (Max subscription)");
  }

  return new Promise((resolve, reject) => {
    // Strip ANTHROPIC_API_KEY from env so CLI uses Max subscription auth
    const env = { ...process.env };
    delete env.ANTHROPIC_API_KEY;

    const args = [
      "--print",
      ...(opts?.disableTools ? [] : ["--dangerously-skip-permissions"]),
      "--model", model,
      "--max-turns", "10",
      ...(opts?.systemPrompt ? ["--system-prompt", opts.systemPrompt] : []),
      "-", // read prompt from stdin
    ];

    const child = spawn(
      claudePath,
      args,
      {
        stdio: ["pipe", "pipe", "pipe"],
        env,
      },
    );

    // Pipe prompt via stdin to avoid ARG_MAX limits on large prompts
    child.stdin.write(prompt);
    child.stdin.end();

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    // Manual timeout since spawn() doesn't support the timeout option
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`Claude CLI timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(
          new Error(
            `Claude CLI exited with code ${code}: ${stderr || stdout}`,
          ),
        );
      }
    });
  });
}

async function runClaudeAPI(
  prompt: string,
  opts?: RunClaudeOpts,
): Promise<string> {
  const config = getConfig();

  if (!config.ANTHROPIC_API_KEY) {
    throw new Error(
      "CLAUDE_BACKEND=api but ANTHROPIC_API_KEY is not set. Set the key or switch to CLAUDE_BACKEND=cli.",
    );
  }

  log.debug("Running Claude via API");

  // Dynamic import to avoid loading the SDK when using CLI mode
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const client = new Anthropic({ apiKey: config.ANTHROPIC_API_KEY });

  const model = resolveApiModel(opts?.model ?? config.CLAUDE_MODEL);

  // Use prompt caching on system prompts — they're large and stable across batch calls.
  // cache_control: ephemeral keeps the prefix cached for ~5 min, cutting input costs ~90%.
  const systemParam = opts?.systemPrompt
    ? [{ type: "text" as const, text: opts.systemPrompt, cache_control: { type: "ephemeral" as const } }]
    : undefined;

  const response = await client.messages.create({
    model,
    max_tokens: opts?.maxTokens ?? 4096,
    ...(opts?.temperature != null ? { temperature: opts.temperature } : {}),
    ...(systemParam ? { system: systemParam } : {}),
    messages: [{ role: "user", content: prompt }],
  });

  const text =
    response.content[0].type === "text" ? response.content[0].text : "";
  return text.trim();
}

/**
 * Run a prompt through Claude and get structured JSON output.
 *
 * - API mode: Uses tool_use with forced tool_choice for guaranteed valid JSON.
 * - CLI mode: Falls back to text generation + extractJsonWithKey parsing.
 *
 * Returns the parsed object or null if extraction fails.
 */
export async function runClaudeStructured<T = Record<string, unknown>>(
  prompt: string,
  opts: StructuredOutputOpts,
): Promise<T | null> {
  const config = getConfig();

  if (config.CLAUDE_BACKEND === "api") {
    return runClaudeStructuredAPI<T>(prompt, opts);
  }

  // CLI fallback: text generation + JSON extraction
  if (process.env.OLLAMA_DISCOVERY_DIRECT === "true") {
    const text = await runLocalOllama(prompt, opts, opts.inputSchema);
    const parsed = JSON.parse(text);
    if (!Object.hasOwn(parsed, opts.fallbackKey)) throw new Error("Ollama assessment omitted its result field");
    return parsed as T;
  }
  return extractJsonWithKey<T>(await runClaudeCLI(prompt, opts), opts.fallbackKey);
}

async function runClaudeStructuredAPI<T>(
  prompt: string,
  opts: StructuredOutputOpts,
): Promise<T | null> {
  const config = getConfig();

  if (!config.ANTHROPIC_API_KEY) {
    throw new Error(
      "CLAUDE_BACKEND=api but ANTHROPIC_API_KEY is not set.",
    );
  }

  log.debug({ tool: opts.toolName }, "Running Claude structured output via API");

  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const client = new Anthropic({ apiKey: config.ANTHROPIC_API_KEY });

  const model = resolveApiModel(opts.model ?? config.CLAUDE_MODEL);

  const systemParam = opts.systemPrompt
    ? [{ type: "text" as const, text: opts.systemPrompt, cache_control: { type: "ephemeral" as const } }]
    : undefined;

  const response = await client.messages.create({
    model,
    max_tokens: opts.maxTokens ?? 4096,
    ...(opts.temperature != null ? { temperature: opts.temperature } : {}),
    ...(systemParam ? { system: systemParam } : {}),
    messages: [{ role: "user", content: prompt }],
    tools: [
      {
        name: opts.toolName,
        description: `Return structured ${opts.toolName} data.`,
        input_schema: opts.inputSchema as any,
      },
    ],
    tool_choice: { type: "tool" as const, name: opts.toolName },
  });

  const toolBlock = response.content.find((b: any) => b.type === "tool_use");
  if (!toolBlock || toolBlock.type !== "tool_use") {
    log.warn("No tool_use block in structured response, falling back to text extraction");
    const text = response.content.find((b: any) => b.type === "text");
    if (text && text.type === "text") {
      return extractJsonWithKey<T>(text.text, opts.fallbackKey);
    }
    return null;
  }

  return (toolBlock as any).input as T;
}
