// Runtime configuration, surfaced from the project .env via next.config.ts.

// The official ZEN mainnet chain id. Any other network the app targets is
// treated as a testnet environment (see TestnetBanner).
export const MAINNET_CHAIN_ID = 26514;
const TESTNET_CHAIN_ID = 2651420;

// Human-readable network name, used when registering the chain in the wallet
// (wallet_addEthereumChain). Hardcoded for the known Horizen chain ids.
function chainNameFor(chainId: number): string {
  if (chainId === MAINNET_CHAIN_ID) return "Horizen Mainchain";
  if (chainId === TESTNET_CHAIN_ID) return "Horizen Testnet";
  return "Horizen";
}

const chainId = Number(process.env.NEXT_PUBLIC_CHAIN_ID ?? "31337");
const NATIVE_CURRENCY = process.env.NEXT_PUBLIC_NATIVE_CURRENCY ?? "ETH";

if (process.env.NODE_ENV === "production") {
  const missing = (
    [
      ["NEXT_PUBLIC_RPC", process.env.NEXT_PUBLIC_RPC],
      ["NEXT_PUBLIC_CHAIN_ID", process.env.NEXT_PUBLIC_CHAIN_ID],
      ["NEXT_PUBLIC_CONTRACT_STAKER", process.env.NEXT_PUBLIC_CONTRACT_STAKER],
      ["NEXT_PUBLIC_CONTRACT_TOKEN", process.env.NEXT_PUBLIC_CONTRACT_TOKEN],
      ["NEXT_PUBLIC_SUBGRAPH", process.env.NEXT_PUBLIC_SUBGRAPH],
    ] as const
  )
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables for production build: ${missing.join(", ")}`
    );
  }
}

export const CONFIG = {
  rpc: process.env.NEXT_PUBLIC_RPC ?? "http://localhost:8545",
  chainId,
  contractStaker: process.env.NEXT_PUBLIC_CONTRACT_STAKER as string,
  contractToken: process.env.NEXT_PUBLIC_CONTRACT_TOKEN as string,
  subgraph: process.env.NEXT_PUBLIC_SUBGRAPH as string,
  explorerUrl: process.env.NEXT_PUBLIC_EXPLORER_URL ?? "",
  // Terms & Conditions link (footer). Defaults to the Horizen staking terms when unset.
  termsUrl: process.env.NEXT_PUBLIC_TERMS_URL ?? "https://horizen.io/staking-terms",
  // Used to register the network in the wallet (wallet_addEthereumChain) when it
  // isn't known yet, so "switch network" can succeed instead of erroring 4902.
  chainName: chainNameFor(chainId),
  nativeCurrency: NATIVE_CURRENCY,
  // Default on: present a single aggregated position and route "stake" to
  // stakeMore on the existing deposit. Disable to expose the multi-deposit model.
  singlePosition: (process.env.NEXT_PUBLIC_SINGLE_POSITION ?? "true") !== "false",
  // Onboarding links (dashboard hero): where to bridge ETH / ZEN in from Base.
  // Optional — the step renders as plain (non-linked) text when unset.
  bridgeEthUrl: process.env.NEXT_PUBLIC_BRIDGE_ETH_URL ?? "",
  bridgeZenUrl: process.env.NEXT_PUBLIC_BRIDGE_ZEN_URL ?? "",
  // CoinGecko coin id used to price the staked token in USD ("Staked value"
  // stat). "zencash" is correct — CoinGecko kept ZEN's pre-rebrand slug (the
  // "horizen" id does not exist there; verified via /api/v3/search?query=horizen).
  // Leave blank to disable the price fetch entirely, e.g. when the deployed
  // token isn't real ZEN (a devnet mock).
  coingeckoId: process.env.NEXT_PUBLIC_COINGECKO_ID ?? "zencash",
  // Block gap above which the subgraph is considered behind the chain head
  // (useSubgraphHealth). A couple of blocks of lag is normal; only flag a
  // meaningful gap to avoid false positives.
  behindThreshold: Number(process.env.NEXT_PUBLIC_BEHIND_THRESHOLD ?? "30"),
  // Consecutive over-threshold checks required before surfacing the "stale"
  // banner — absorbs transient lag instead of flashing the banner on a single
  // slow poll.
  behindThresholdAttempt: Number(process.env.NEXT_PUBLIC_BEHIND_THRESHOLD_ATTEMPT ?? "4"),
  // Seconds between subgraph health checks (also the retry cadence while
  // over-threshold and not yet at behindThresholdAttempt).
  behindThresholdAttemptInterval: Number(
    process.env.NEXT_PUBLIC_BEHIND_THRESHOLD_ATTEMPT_INTERVAL ?? "30"
  ),
} as const;
