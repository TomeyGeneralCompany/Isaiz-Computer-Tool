"use client";

import { useCallback, useState } from "react";
import { Contract, Interface, parseEther } from "ethers";
import { useWallet } from "./wallet";
import { getSignedContracts } from "./contracts";
import { CONFIG } from "./config";
import { ZEN_STAKER_ABI } from "./abi";
import { decodeStakeError } from "./errors";

export type StakeStatus =
  | "idle"
  | "approve-wallet" // waiting for the user to confirm the approval in the wallet
  | "approve-pending" // approval tx broadcast, awaiting on-chain confirmation
  | "stake-wallet" // waiting for the user to confirm the stake in the wallet
  | "stake-pending" // stake tx broadcast, awaiting on-chain confirmation
  | "success"
  | "error";

// Resolved by `stake()` so the caller can run its own post-success side
// effects (learn the deposit id, refresh balances, close a dialog…) right
// where the submit happened, instead of reacting to a status change via a
// separate effect.
export type StakeOutcome = { ok: true; depositId: bigint | null } | { ok: false };

interface StakeResult {
  status: StakeStatus;
  txHash: string | null;
  depositId: bigint | null;
  error: string | null;
  // How many steps this run has: 4 when an approval is required (approve →
  // confirm → stake → confirm), 2 when the allowance already covers the amount
  // (stake → confirm). Lets the UI render "Step n/total".
  totalSteps: number;
  // Create a new deposit, or — when existingDepositId is given — add to it via
  // stakeMore. Both paths approve the token if needed, then stake.
  stake: (amount: string, existingDepositId?: bigint | null) => Promise<StakeOutcome>;
  reset: () => void;
}

function parseDepositId(logs: readonly { topics: string[]; data: string }[]): bigint | null {
  const iface = new Interface(ZEN_STAKER_ABI);
  for (const log of logs) {
    try {
      const parsed = iface.parseLog(log);
      if (parsed?.name === "StakeDeposited") return parsed.args[1] as bigint;
    } catch {
      /* not our event */
    }
  }
  return null;
}

export function useStake(): StakeResult {
  const { signer, address } = useWallet();
  const [status, setStatus] = useState<StakeStatus>("idle");
  const [txHash, setTxHash] = useState<string | null>(null);
  const [depositId, setDepositId] = useState<bigint | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [totalSteps, setTotalSteps] = useState<number>(2);

  const reset = useCallback(() => {
    setStatus("idle");
    setTxHash(null);
    setDepositId(null);
    setError(null);
    setTotalSteps(2);
  }, []);

  const stake = useCallback(
    async (amountStr: string, existingDepositId?: bigint | null): Promise<StakeOutcome> => {
      if (!signer || !address) {
        setError("Connect your wallet first.");
        setStatus("error");
        return { ok: false };
      }
      setError(null);
      setDepositId(null);
      setTxHash(null);

      try {
        const amount = parseEther(amountStr);
        // v1: delegation is not surfaced — delegatee & claimer default to self.
        const self = address;
        const { staker, token } = getSignedContracts(signer);

        // approve-if-needed: the ZEN token is a LayerZero OFT without EIP-2612
        // permit, so staking always goes through a standard ERC-20 approval.
        const allowance: bigint = await token.allowance(address, CONFIG.contractStaker);
        const needsApproval = allowance < amount;
        setTotalSteps(needsApproval ? 4 : 2);
        if (needsApproval) {
          setStatus("approve-wallet");
          const approveTx = await token.approve(CONFIG.contractStaker, amount);
          setStatus("approve-pending");
          await approveTx.wait();
        }

        setStatus("stake-wallet");
        // Increase an existing position via stakeMore, otherwise open a new one.
        if (existingDepositId != null) {
          const tx = await staker.stakeMore(existingDepositId, amount);
          setTxHash(tx.hash);
          setStatus("stake-pending");
          await tx.wait();
          setDepositId(existingDepositId);
          setStatus("success");
          return { ok: true, depositId: existingDepositId };
        }

        const stakerWrite = staker as Contract;
        const tx = await stakerWrite["stake(uint256,address)"](amount, self);
        setTxHash(tx.hash);
        setStatus("stake-pending");
        const receipt = await tx.wait();
        const newDepositId = parseDepositId(receipt?.logs ?? []);
        setDepositId(newDepositId);
        setStatus("success");
        return { ok: true, depositId: newDepositId };
      } catch (e) {
        setError(decodeStakeError(e));
        setStatus("error");
        return { ok: false };
      }
    },
    [signer, address]
  );

  return { status, txHash, depositId, error, totalSteps, stake, reset };
}
