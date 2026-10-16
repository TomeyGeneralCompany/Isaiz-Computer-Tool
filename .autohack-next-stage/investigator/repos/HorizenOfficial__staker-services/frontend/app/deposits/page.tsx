"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { CONFIG } from "@/lib/config";
import { useWallet } from "@/lib/wallet";
import { useDeposits } from "@/lib/useDeposits";
import { DepositsTable } from "@/components/DepositsTable";

export default function DepositsPage() {
  const router = useRouter();
  const { address, isCorrectChain } = useWallet();
  const active = address && isCorrectChain ? address : null;
  const { deposits, hasLoadedOnce } = useDeposits(active);

  // Single-position manages everything from the dashboard — unless the
  // wallet actually holds more than one deposit (legacy or created
  // elsewhere), in which case it falls back to this multi-deposit table
  // instead of silently hiding the extra deposit's balance. We can't know
  // the real count until the first load settles, so wait for that before
  // deciding (avoids redirecting away from a multi-deposit wallet before
  // its deposits have loaded).
  const checked = !active || hasLoadedOnce;
  const showTable = !CONFIG.singlePosition || deposits.length > 1;

  useEffect(() => {
    if (CONFIG.singlePosition && checked && !showTable) router.replace("/");
  }, [checked, showTable, router]);

  if (CONFIG.singlePosition && (!checked || !showTable)) return null;
  return <DepositsTable />;
}
