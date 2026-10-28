# Progress-aware local model requests

The old audit client applied a 15-minute request deadline before acquiring the
shared inference lock, then asked Ollama for a non-streaming response. Queueing,
prompt processing, active generation and a stalled server were indistinguishable.

Audits now use Ollama's documented streaming chat protocol through both the direct
and Qwen-Agent adapters. The 15-minute inactivity clock starts after acquiring the
lock and resets only when content, thinking or tool-call output arrives. Blank
frames do not reset it. The existing audit deadline and operator cancellation
remain authoritative, including while waiting for the lock. No model action is
executed until the complete response passes the existing controller validation.

Progress logs contain character/tool-call counts, not thinking text. The dashboard
displays generation activity separately from file reads and tests. A silent initial
prompt evaluation can still exhaust the inactivity window; this change does not
prove whether a particular host is loading, evaluating or stalled before its first
output. JSON-only compatibility responses cannot expose intermediate progress.

References:
- https://docs.ollama.com/api/streaming
- https://docs.ollama.com/capabilities/tool-calling
- https://github.com/ollama/ollama/pull/18479 documents a separate upstream
  structured-output/thinking issue. Its applicability requires the host's Ollama
  version and thinking settings; the dashboard timeout alone does not establish it.

Regression tests use an owned loopback server for active output beyond the idle
window, queued cancellation, silence, empty frames, truncated streams, UTF-8,
response bounds and tool calls. The production workflow fixture streams fragmented
actions and performs actual isolated probes in CI. Qwen-Agent's real package is
exercised separately; the fixture model is scripted, not a real Qwen inference run.
