// The acceptance harness consumes only nonsecret settings. dotenv matches the
// application parser; inherited environment values keep precedence.
import "dotenv/config";
console.log(JSON.stringify({
  model:process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",
  ollamaUrl:process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat",
  dbPath:process.env.DB_PATH || "data/bounty.db",
}));
