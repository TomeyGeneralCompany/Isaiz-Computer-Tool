"use client";

import { useEffect } from "react";

// Runs `fn` once, then every `intervalMs` while `enabled`. Polling pauses while
// the browser tab is hidden — no wasted RPC/subgraph calls in the background —
// and catches up with an immediate run when the tab becomes visible again.
//
// `fn` should be a stable reference (useCallback); a change in its identity
// re-triggers the initial run, which preserves the existing "reload when the
// address changes" behaviour of the data hooks.
export function usePolling(fn: () => void, intervalMs: number, enabled = true) {
  useEffect(() => {
    fn(); // initial load (and re-run whenever fn identity changes)
    if (!enabled) return;

    let id: ReturnType<typeof setInterval> | null = null;
    const start = () => {
      if (id == null) id = setInterval(fn, intervalMs);
    };
    const stop = () => {
      if (id != null) {
        clearInterval(id);
        id = null;
      }
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        fn(); // catch up on whatever changed while hidden
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [fn, intervalMs, enabled]);
}
