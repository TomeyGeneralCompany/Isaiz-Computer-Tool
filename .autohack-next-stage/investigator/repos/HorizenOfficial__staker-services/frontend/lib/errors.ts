import { Interface } from "ethers";
import { ZEN_STAKER_ABI } from "./abi";
import { CONFIG } from "./config";

const iface = new Interface(ZEN_STAKER_ABI);

// Map a thrown error from a contract interaction to a human-readable message.
export function decodeStakeError(err: unknown): string {
  const e = err as { code?: string; data?: string; message?: string; reason?: string };

  // User rejected the request in the wallet
  if (e?.code === "ACTION_REJECTED" || e?.message?.includes("user rejected")) {
    return "Transaction rejected in wallet.";
  }
  if (e?.message?.includes("insufficient funds")) {
    return `Not enough ${CONFIG.nativeCurrency} to cover gas.`;
  }

  // Try to decode a custom Solidity error
  const data =
    e?.data ??
    (err as { info?: { error?: { data?: string } } })?.info?.error?.data;
  if (typeof data === "string" && data.startsWith("0x") && data.length >= 10) {
    try {
      const decoded = iface.parseError(data);
      switch (decoded?.name) {
        case "Staker__InvalidAddress":
          return "Invalid address (zero address not allowed).";
        case "Staker__Unauthorized":
          return "Unauthorized for this operation.";
        case "Staker__InvalidRewardRate":
          return "Invalid reward rate.";
        case "Staker__ExpiredDeadline":
          return "Permit signature expired — please try again.";
        case "Staker__InvalidSignature":
          return "Invalid permit signature.";
        case "StakerPermitAndStake__UnauthorizedToken":
          return "This token does not support permit staking.";
        default:
          return decoded?.name ?? "Transaction failed.";
      }
    } catch {
      /* not a decodable custom error */
    }
  }

  return e?.reason ?? e?.message ?? "Transaction failed.";
}
