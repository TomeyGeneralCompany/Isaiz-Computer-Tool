"use client";

import { useSubgraphHealth } from "@/lib/useSubgraphHealth";

export function SubgraphHealthBanner() {
  const health = useSubgraphHealth();

  if (health.status === "ok" || health.status === "checking") return null;

  let message: string;
  let severity: "error" | "warning" = "warning";

  switch (health.status) {
    case "desynced":
      severity = "error";
      message = `Subgraph is out of sync — its index is ${health.ahead} block${health.ahead === 1 ? "" : "s"} ahead of the chain, which means the chain was restarted. Listed deposits and history are from a stale chain and may be wrong.`;
      break;
    case "errors":
      severity = "error";
      message = "Subgraph reported indexing errors — deposit lists and history may be incomplete or out of date.";
      break;
    case "unreachable":
      severity = "error";
      message = "Subgraph is unreachable — deposit lists and history are unavailable until it is back online.";
      break;
    case "stale":
      severity = "warning";
      message = `Subgraph is ${health.behind} blocks behind the chain — some data may be out of date.`;
      break;
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className={`hl-alert hl-alert-${severity}`}
      style={{ margin: "var(--hl-space-4) clamp(20px, 4vw, 28px) 0" }}
    >
      {message}
    </div>
  );
}
