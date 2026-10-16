"use client";

import { useCallback, useRef, useState } from "react";
import { CONFIG } from "./config";
import { getReadProvider } from "./contracts";
import { fetchSubgraphMeta } from "./subgraph";
import { usePolling } from "./usePolling";

const POLL_MS = CONFIG.behindThresholdAttemptInterval * 1000;

export type SubgraphHealth =
  | { status: "checking" }
  | { status: "ok"; behind: number }
  | { status: "stale"; behind: number } // indexed head trails the chain
  | { status: "desynced"; ahead: number } // indexed head is AHEAD of the chain → chain was reset
  | { status: "errors" } // graph-node reported indexing errors
  | { status: "unreachable" }; // can't query the subgraph

export function useSubgraphHealth(): SubgraphHealth {
  const [health, setHealth] = useState<SubgraphHealth>({ status: "checking" });
  // Consecutive over-threshold checks so far — a single slow poll doesn't
  // flash the "stale" banner; only sustained lag (behindThresholdAttempt
  // polls in a row) does.
  const staleAttempts = useRef(0);

  const check = useCallback(async () => {
    let subgraphBlock: number;
    let hasErrors: boolean;
    try {
      const meta = await fetchSubgraphMeta();
      subgraphBlock = meta.block;
      hasErrors = meta.hasIndexingErrors;
    } catch {
      staleAttempts.current = 0;
      setHealth({ status: "unreachable" });
      return;
    }
    if (hasErrors) {
      staleAttempts.current = 0;
      setHealth({ status: "errors" });
      return;
    }

    let chainBlock: number;
    try {
      chainBlock = await getReadProvider().getBlockNumber();
    } catch {
      // Reached the subgraph but not the chain — can't compare; treat as ok.
      staleAttempts.current = 0;
      setHealth({ status: "ok", behind: 0 });
      return;
    }

    if (subgraphBlock > chainBlock) {
      staleAttempts.current = 0;
      setHealth({ status: "desynced", ahead: subgraphBlock - chainBlock });
      return;
    }

    const behind = chainBlock - subgraphBlock;
    if (behind > CONFIG.behindThreshold) {
      staleAttempts.current += 1;
      if (staleAttempts.current >= CONFIG.behindThresholdAttempt) {
        setHealth({ status: "stale", behind });
      }
      // else: keep the current status and retry on the next poll instead of
      // surfacing the banner immediately.
      return;
    }

    staleAttempts.current = 0;
    setHealth({ status: "ok", behind });
  }, []);

  usePolling(check, POLL_MS);

  return health;
}
