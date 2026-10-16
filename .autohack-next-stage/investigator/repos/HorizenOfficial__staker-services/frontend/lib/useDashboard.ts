"use client";

import { useCallback, useEffect, useState } from "react";
import { getReadContracts } from "./contracts";
import { fetchUserDepositIds } from "./subgraph";
import { usePolling } from "./usePolling";

const POLL_MS = 20_000;

export interface GlobalState {
  totalStaked: bigint;
  totalEarningPower: bigint;
  rewardRate: bigint;
  rewardEndTime: bigint;
}

export function useGlobalState() {
  const [data, setData] = useState<GlobalState | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const { staker } = getReadContracts();
      const r = await staker.getGlobalState();
      setData({
        totalStaked: r[0] as bigint,
        totalEarningPower: r[1] as bigint,
        rewardRate: r[2] as bigint,
        rewardEndTime: r[3] as bigint,
      });
      setError(null);
    } catch {
      setError("Unable to read on-chain state.");
    }
  }, []);

  usePolling(load, POLL_MS);

  return { data, error, reload: load };
}

export interface UserSummary {
  totalStaked: bigint;
  totalEarningPower: bigint;
  totalUnclaimed: bigint | null; // null when deposit IDs are unavailable (subgraph down)
  depositCount: number;
}

export function useUserSummary(address: string | null) {
  const [data, setData] = useState<UserSummary | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!address) {
      setData(null);
      return;
    }
    setLoading(true);
    try {
      const { staker } = getReadContracts();
      // Staked + earning power need no deposit IDs.
      const [totalStaked, totalEarningPower] = await staker.getDepositorSummary(address);

      // Unclaimed needs the deposit IDs from the subgraph.
      let totalUnclaimed: bigint | null = null;
      let depositCount = 0;
      try {
        const ids = await fetchUserDepositIds(address);
        depositCount = ids.length;
        if (ids.length > 0) {
          const full = await staker.getDepositorFullSummary(address, ids);
          totalUnclaimed = full[2] as bigint;
        } else {
          totalUnclaimed = 0n;
        }
      } catch {
        // subgraph unavailable — leave unclaimed unknown, still show staked/EP
      }

      setData({
        totalStaked: totalStaked as bigint,
        totalEarningPower: totalEarningPower as bigint,
        totalUnclaimed,
        depositCount,
      });
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [address]);

  usePolling(load, POLL_MS, !!address);

  return { data, loading, reload: load };
}

// Smoothly interpolates unclaimed rewards between polls.
// estimate = base + (rewardRate * userEP / totalEP) * secondsElapsed, capped at rewardEndTime.
export function useLiveReward(
  base: bigint | null,
  rewardRate: bigint,
  userEarningPower: bigint,
  totalEarningPower: bigint,
  rewardEndTime: bigint
): bigint | null {
  const [value, setValue] = useState<bigint | null>(base);

  useEffect(() => {
    const anchor = Date.now();
    const tick = () => {
      if (base === null || totalEarningPower === 0n || userEarningPower === 0n) {
        setValue(base);
        return;
      }
      const perSecond = (rewardRate * userEarningPower) / totalEarningPower;
      const nowSec = Math.floor(Date.now() / 1000);
      const endSec = rewardEndTime === 0n ? nowSec : Number(rewardEndTime);
      const cappedNow = Math.min(nowSec, endSec);
      const elapsed = cappedNow - Math.floor(anchor / 1000);
      setValue(elapsed <= 0 ? base : base + perSecond * BigInt(elapsed));
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [base, rewardRate, userEarningPower, totalEarningPower, rewardEndTime]);

  return value;
}
