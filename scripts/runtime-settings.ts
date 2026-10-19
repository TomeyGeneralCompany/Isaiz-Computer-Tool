// The acceptance harness consumes only nonsecret settings. dotenv matches the
// application parser; inherited environment values keep precedence.
import "dotenv/config";
import { hostModelTimeout } from "./model-check-settings";
console.log(JSON.stringify({
  discoveryDirect:process.env.OLLAMA_DISCOVERY_DIRECT === "true",
  assessmentModel:process.env.OLLAMA_MODEL || process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",
  toolProtocol:process.env.LOCAL_OLLAMA_TOOL_PROTOCOL || "json",
  agentTimeoutMs:hostModelTimeout(),
  model:process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",
  ollamaUrl:process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat",
  dbPath:process.env.DB_PATH || "data/bounty.db",
}));
