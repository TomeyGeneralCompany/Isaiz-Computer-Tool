"use client";

import { CONFIG, MAINNET_CHAIN_ID } from "@/lib/config";

// Full-width strip under the top bar, shown whenever the app targets any
// network other than ZEN mainnet. Based on the configured chain id (the network
// the dApp talks to), so it is correct even before a wallet is connected.
export function TestnetBanner() {
  if (CONFIG.chainId === MAINNET_CHAIN_ID) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        background: "transparent",
        borderBottom: "1px solid var(--hl-grey)",
        color: "var(--hl-sunrise)",
        fontFamily: "var(--font-sans)",
        textAlign: "center",
        padding: "11px 16px",
        fontWeight: 600,
        fontSize: 13,
        letterSpacing: "0.04em",
      }}
    >
      You are in testnet environment!
    </div>
  );
}
