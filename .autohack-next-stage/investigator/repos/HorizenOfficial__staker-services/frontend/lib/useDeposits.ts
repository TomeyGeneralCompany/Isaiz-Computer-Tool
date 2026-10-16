"use client";

import { useCallback, useMemo, useState } from "react";
import { Interface } from "ethers";
import { getReadContracts, getReadProvider } from "./contracts";
import { fetchUserDepositIds } from "./subgraph";
import { useLearnedDeposits } from "./learnedDeposits";
import { usePolling } from "./usePolling";
import { CONFIG } from "./config";
import { ZEN_STAKER_ABI } from "./abi";

const POLL_MS = 20_000;

export interface DepositDetail {
  depositId: bigint;
  balance: bigint;
  earningPower: bigint;
  unclaimedRewards: bigint;
}

const stakerInterface = new Interface(ZEN_STAKER_ABI);

// Owner is an indexed event param, so this is a targeted log filter — not a
// full-history scan — used only as a fallback when the subgraph and the
// learned-deposits cache together still don't add up to the on-chain total
// (e.g. a deposit created by calling the contract directly, bypassing this
// UI, that the subgraph hasn't indexed either). Deposit ownership never
// changes after creation, so this is a complete, chain-only ID enumeration.
async function fetchDepositIdsFromChain(owner: string): Promise<bigint[]> {
  const topics = stakerInterface.encodeFilterTopics("StakeDeposited", [owner]);
  const logs = await getReadProvider().getLogs({
    address: CONFIG.contractStaker,
    topics,
    fromBlock: 0,
    toBlock: "latest",
  });
  const ids = new Set<string>();
  for (const log of logs) {
    const parsed = stakerInterface.parseLog(log);
    if (parsed) ids.add((parsed.args[1] as bigint).toString());
  }
  return Array.from(ids).map((s) => BigInt(s));
}

export interface DepositsState {
  deposits: DepositDetail[];
  loading: boolean;
  error: string | null; // set only on a hard failure (no data to show)
  subgraphDown: boolean;
  // True once the first load attempt (for the current address) has settled —
  // lets callers wait for a real deposit count before deciding anything
  // (e.g. whether to redirect away from a multi-deposit view).
  hasLoadedOnce: boolean;
  reload: () => Promise<void>;
}

// Deposit IDs come from the subgraph (not enumerable on-chain); per-deposit
// detail is read live from the chain via getDepositsInfo for freshness.
export function useDeposits(address: string | null): DepositsState {
  const { learned } = useLearnedDeposits();
  const [deposits, setDeposits] = useState<DepositDetail[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subgraphDown, setSubgraphDown] = useState(false);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);

  // Deposit IDs learned from stake receipts this session (fresh before indexing).
  const learnedIds = useMemo(
    () => (address ? (learned[address.toLowerCase()] ?? []).map((s) => BigInt(s)) : []),
    [learned, address]
  );

  const load = useCallback(async () => {
    if (!address) {
      setDeposits([]);
      setHasLoadedOnce(true);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // Subgraph is the primary ID source; learned IDs cover the indexing gap
      // and keep things working if the subgraph is momentarily down.
      let subgraphIds: bigint[] = [];
      let subgraphFailed = false;
      try {
        subgraphIds = await fetchUserDepositIds(address);
        setSubgraphDown(false);
      } catch {
        subgraphFailed = true;
        setSubgraphDown(true);
      }

      let ids = Array.from(
        new Set([...subgraphIds, ...learnedIds].map((b) => b.toString()))
      ).map((s) => BigInt(s));

      const { staker } = getReadContracts();
      const fetchDetail = async (idList: bigint[]): Promise<DepositDetail[]> => {
        const [balances, , earningPowers, unclaimedRewards] = await staker.getDepositsInfo(idList);
        return idList.map((id, i) => ({
          depositId: id,
          balance: balances[i] as bigint,
          earningPower: earningPowers[i] as bigint,
          unclaimedRewards: unclaimedRewards[i] as bigint,
        }));
      };

      let detail = ids.length > 0 ? await fetchDetail(ids) : [];
      const knownTotal = detail.reduce((a, d) => a + d.balance, 0n);

      // Cross-check against the chain-only aggregate (no ID lookup needed): if
      // it reports more than the deposits we know about add up to, at least
      // one deposit id is missing from both the subgraph and the learned
      // cache — fall back to a targeted chain log scan to recover it.
      try {
        const [chainTotal] = await staker.getDepositorSummary(address);
        if ((chainTotal as bigint) > knownTotal) {
          const chainIds = await fetchDepositIdsFromChain(address);
          const merged = Array.from(
            new Set([...ids, ...chainIds].map((b) => b.toString()))
          ).map((s) => BigInt(s));
          if (merged.length !== ids.length) {
            ids = merged;
            detail = await fetchDetail(ids);
          }
        }
      } catch {
        // Best-effort cross-check; keep whatever was already resolved above.
      }

      if (ids.length === 0) {
        setDeposits([]);
        // Only surface an error if we genuinely couldn't reach the ID source.
        if (subgraphFailed && learnedIds.length === 0)
          setError("Cannot load deposits — subgraph unavailable.");
        return;
      }

      // Keep only positions that still matter: open balance, or rewards still
      // claimable after a full withdrawal.
      setDeposits(
        detail
          .filter((d) => d.balance > 0n || d.unclaimedRewards > 0n)
          .sort((a, b) => (a.depositId < b.depositId ? -1 : 1))
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load deposits.");
    } finally {
      setLoading(false);
      setHasLoadedOnce(true);
    }
  }, [address, learnedIds]);

  usePolling(load, POLL_MS, !!address);

  return { deposits, loading, error, subgraphDown, hasLoadedOnce, reload: load };
}
