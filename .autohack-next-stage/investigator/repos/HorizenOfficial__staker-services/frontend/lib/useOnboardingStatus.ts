"use client";

import { useCallback, useState } from "react";
import { getReadContracts, getReadProvider } from "./contracts";
import { usePolling } from "./usePolling";

const POLL_MS = 15_000;

// Drives the hero onboarding checklist ("Bridge ETH" / "Bridge ZEN" / "Stake")
// — each step should read as done once the wallet demonstrably has taken it,
// independent of the "staked" flag which the dashboard already tracks via the
// subgraph/chain summary.
export function useOnboardingStatus(address: string | null) {
  const [hasEth, setHasEth] = useState(false);
  const [hasZen, setHasZen] = useState(false);

  const load = useCallback(async () => {
    if (!address) {
      setHasEth(false);
      setHasZen(false);
      return;
    }
    try {
      const provider = getReadProvider();
      const { token } = getReadContracts();
      const [ethBalance, zenBalance] = await Promise.all([
        provider.getBalance(address),
        token.balanceOf(address) as Promise<bigint>,
      ]);
      setHasEth(ethBalance > 0n);
      setHasZen(zenBalance > 0n);
    } catch {
      // keep the last known state on a transient read failure
    }
  }, [address]);

  usePolling(load, POLL_MS);

  return { hasEth, hasZen };
}
