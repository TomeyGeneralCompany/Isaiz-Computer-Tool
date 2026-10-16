"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";

// Deposit IDs learned from stake receipts, keyed by lowercased owner address.
// These let the UI know about a just-created deposit immediately — before the
// subgraph indexes it — and survive both subgraph downtime/lag and a page
// refresh (persisted to localStorage; a refresh right after staking, before
// the subgraph has caught up, would otherwise show the position as empty).
type LearnedMap = Record<string, string[]>;

interface LearnedDepositsCtx {
  learned: LearnedMap;
  add: (address: string, id: bigint) => void;
}

const Ctx = createContext<LearnedDepositsCtx | null>(null);
const STORAGE_KEY = "zenstaker:learnedDeposits";

function loadInitial(): LearnedMap {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as LearnedMap) : {};
  } catch {
    return {};
  }
}

function persist(map: LearnedMap) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    /* storage unavailable (private mode, quota, ...) — in-memory state still works */
  }
}

export function LearnedDepositsProvider({ children }: { children: React.ReactNode }) {
  const [learned, setLearned] = useState<LearnedMap>(loadInitial);

  const add = useCallback((address: string, id: bigint) => {
    const key = address.toLowerCase();
    const idStr = id.toString();
    setLearned((prev) => {
      const cur = prev[key] ?? [];
      if (cur.includes(idStr)) return prev;
      const next = { ...prev, [key]: [...cur, idStr] };
      persist(next);
      return next;
    });
  }, []);

  const value = useMemo(() => ({ learned, add }), [learned, add]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLearnedDeposits(): LearnedDepositsCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useLearnedDeposits must be used within LearnedDepositsProvider");
  return ctx;
}
