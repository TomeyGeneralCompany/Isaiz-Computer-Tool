"use client";

import { useCallback, useState } from "react";
import { parseEther } from "ethers";
import { useWallet } from "./wallet";
import { getSignedContracts } from "./contracts";
import { CONFIG } from "./config";
import { decodeStakeError } from "./errors";
import type { DepositDetail } from "./useDeposits";

export type ActionKind = "claim" | "claimAll" | "stakeMore" | "withdraw" | "withdrawAll";

// A single step of a multi-tx action. Each on-chain tx is two steps: a
// wallet-confirm followed by waiting for the mined confirmation.
export interface ActionStep {
  n: number; // 1-based step index
  total: number; // total steps for this run
  label: string;
}

export interface ActionState {
  kind: ActionKind | null;
  // depositId being acted on, or "all" for claimAll
  target: bigint | "all" | null;
  step: ActionStep | null;
  error: string | null;
}

const IDLE: ActionState = { kind: null, target: null, step: null, error: null };

// "Step 1/2: …" string for display, or null when idle.
export function actionStepLabel(state: ActionState): string | null {
  if (!state.step) return null;
  const { n, total, label } = state.step;
  return `Step ${n}/${total}: ${label}`;
}

export function useDepositActions() {
  const { signer, address } = useWallet();
  const [state, setState] = useState<ActionState>(IDLE);

  const reset = useCallback(() => setState(IDLE), []);

  const require = useCallback(() => {
    if (!signer || !address) throw new Error("Connect your wallet first.");
    return getSignedContracts(signer);
  }, [signer, address]);

  const claim = useCallback(
    async (depositId: bigint): Promise<boolean> => {
      const at = (n: number, label: string): ActionState => ({
        kind: "claim",
        target: depositId,
        step: { n, total: 2, label },
        error: null,
      });
      try {
        const { staker } = require();
        setState(at(1, "Confirm the claim in your wallet"));
        const tx = await staker.claimReward(depositId);
        setState(at(2, "Waiting for the claim to confirm"));
        await tx.wait();
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "claim", target: depositId, step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require]
  );

  const claimAll = useCallback(
    async (deposits: DepositDetail[]): Promise<boolean> => {
      const claimable = deposits.filter((d) => d.unclaimedRewards > 0n);
      if (claimable.length === 0) return true;
      // Two steps per deposit: confirm + wait.
      const total = claimable.length * 2;
      try {
        const { staker } = require();
        let n = 0;
        for (let i = 0; i < claimable.length; i++) {
          const d = claimable[i];
          const pos = `claim ${i + 1}/${claimable.length}`;
          setState({
            kind: "claimAll",
            target: d.depositId,
            step: { n: ++n, total, label: `Confirm ${pos} in your wallet` },
            error: null,
          });
          const tx = await staker.claimReward(d.depositId);
          setState({
            kind: "claimAll",
            target: d.depositId,
            step: { n: ++n, total, label: `Waiting for ${pos} to confirm` },
            error: null,
          });
          await tx.wait();
        }
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "claimAll", target: "all", step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require]
  );

  // Bypassing the UI (staking directly against the contract) can leave a
  // wallet with more than one deposit even in single-position mode. Mirrors
  // claimAll: withdraws every deposit's full balance in one flow instead of
  // making the user withdraw each one individually.
  const withdrawAll = useCallback(
    async (deposits: DepositDetail[], claimRewards: boolean): Promise<boolean> => {
      const withdrawable = deposits.filter((d) => d.balance > 0n);
      if (withdrawable.length === 0) return true;
      // Withdraw is 2 steps per deposit; an optional reward claim adds 2 more
      // for deposits that actually have unclaimed rewards.
      const total = withdrawable.reduce((n, d) => n + (claimRewards && d.unclaimedRewards > 0n ? 4 : 2), 0);
      try {
        const { staker } = require();
        let n = 0;
        for (let i = 0; i < withdrawable.length; i++) {
          const d = withdrawable[i];
          const pos = `withdrawal ${i + 1}/${withdrawable.length}`;
          setState({
            kind: "withdrawAll",
            target: d.depositId,
            step: { n: ++n, total, label: `Confirm ${pos} in your wallet` },
            error: null,
          });
          const tx = await staker.withdraw(d.depositId, d.balance);
          setState({
            kind: "withdrawAll",
            target: d.depositId,
            step: { n: ++n, total, label: `Waiting for ${pos} to confirm` },
            error: null,
          });
          await tx.wait();
          if (claimRewards && d.unclaimedRewards > 0n) {
            const claimPos = `claim ${i + 1}/${withdrawable.length}`;
            setState({
              kind: "withdrawAll",
              target: d.depositId,
              step: { n: ++n, total, label: `Confirm ${claimPos} in your wallet` },
              error: null,
            });
            const claimTx = await staker.claimReward(d.depositId);
            setState({
              kind: "withdrawAll",
              target: d.depositId,
              step: { n: ++n, total, label: `Waiting for ${claimPos} to confirm` },
              error: null,
            });
            await claimTx.wait();
          }
        }
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "withdrawAll", target: "all", step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require]
  );

  // Withdraws a user-entered amount that may exceed any single deposit's
  // balance. Drains the largest deposit first, then cascades into the next
  // largest, and so on, issuing one withdraw tx per deposit touched — so a
  // wallet that ended up with more than one deposit (e.g. by staking directly
  // against the contract, bypassing stakeMore) can still withdraw an
  // arbitrary amount from the single aggregated position view.
  const withdrawAmount = useCallback(
    async (deposits: DepositDetail[], amount: bigint, claimRewards: boolean): Promise<boolean> => {
      const sorted = [...deposits]
        .filter((d) => d.balance > 0n)
        .sort((a, b) => (a.balance < b.balance ? 1 : a.balance > b.balance ? -1 : 0));

      const plan: { deposit: DepositDetail; take: bigint }[] = [];
      let remaining = amount;
      for (const d of sorted) {
        if (remaining <= 0n) break;
        const take = remaining < d.balance ? remaining : d.balance;
        plan.push({ deposit: d, take });
        remaining -= take;
      }
      if (plan.length === 0) return true;

      // Claim only for deposits this withdrawal actually touches — matching
      // the single-deposit behaviour of claiming right after withdrawing from
      // that same deposit, extended to every deposit drained by the cascade.
      const claimTargets = claimRewards ? plan.filter((p) => p.deposit.unclaimedRewards > 0n) : [];
      const total = plan.length * 2 + claimTargets.length * 2;

      let current: bigint = plan[0].deposit.depositId;
      try {
        const { staker } = require();
        let n = 0;
        for (let i = 0; i < plan.length; i++) {
          const { deposit, take } = plan[i];
          current = deposit.depositId;
          const pos = plan.length > 1 ? `withdrawal ${i + 1}/${plan.length}` : "withdrawal";
          setState({ kind: "withdraw", target: deposit.depositId, step: { n: ++n, total, label: `Confirm the ${pos} in your wallet` }, error: null });
          const tx = await staker.withdraw(deposit.depositId, take);
          setState({ kind: "withdraw", target: deposit.depositId, step: { n: ++n, total, label: `Waiting for the ${pos} to confirm` }, error: null });
          await tx.wait();
        }
        for (let i = 0; i < claimTargets.length; i++) {
          const d = claimTargets[i].deposit;
          current = d.depositId;
          const pos = claimTargets.length > 1 ? `claim ${i + 1}/${claimTargets.length}` : "claim";
          setState({ kind: "withdraw", target: d.depositId, step: { n: ++n, total, label: `Confirm the ${pos} in your wallet` }, error: null });
          const tx = await staker.claimReward(d.depositId);
          setState({ kind: "withdraw", target: d.depositId, step: { n: ++n, total, label: `Waiting for the ${pos} to confirm` }, error: null });
          await tx.wait();
        }
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "withdraw", target: current, step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require]
  );

  const stakeMore = useCallback(
    async (depositId: bigint, amountStr: string): Promise<boolean> => {
      try {
        const { staker, token } = require();
        const amount = parseEther(amountStr);

        const allowance: bigint = await token.allowance(address!, CONFIG.contractStaker);
        const needsApproval = allowance < amount;
        const total = needsApproval ? 4 : 2;
        const at = (n: number, label: string): ActionState => ({
          kind: "stakeMore",
          target: depositId,
          step: { n, total, label },
          error: null,
        });

        if (needsApproval) {
          setState(at(1, "Approve token spending in your wallet"));
          const approveTx = await token.approve(CONFIG.contractStaker, amount);
          setState(at(2, "Waiting for the approval to confirm"));
          await approveTx.wait();
        }

        setState(at(needsApproval ? 3 : 1, "Confirm the stake in your wallet"));
        const tx = await staker.stakeMore(depositId, amount);
        setState(at(needsApproval ? 4 : 2, "Waiting for the stake to confirm"));
        await tx.wait();
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "stakeMore", target: depositId, step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require, address]
  );

  const withdraw = useCallback(
    async (
      depositId: bigint,
      amount: bigint,
      claimRewards: boolean
    ): Promise<boolean> => {
      // Withdraw is 2 steps; an optional reward claim adds 2 more.
      const total = claimRewards ? 4 : 2;
      const at = (n: number, label: string): ActionState => ({
        kind: "withdraw",
        target: depositId,
        step: { n, total, label },
        error: null,
      });
      try {
        const { staker } = require();
        // Withdraw first, then claim: a full withdraw drops the deposit's
        // earning power to 0, so a claim immediately after captures every
        // accrued reward with no residual maturing between the two txs.
        setState(at(1, "Confirm the withdrawal in your wallet"));
        const tx = await staker.withdraw(depositId, amount);
        setState(at(2, "Waiting for the withdrawal to confirm"));
        await tx.wait();
        if (claimRewards) {
          setState(at(3, "Confirm the claim in your wallet"));
          const claimTx = await staker.claimReward(depositId);
          setState(at(4, "Waiting for the claim to confirm"));
          await claimTx.wait();
        }
        setState(IDLE);
        return true;
      } catch (e) {
        setState({ kind: "withdraw", target: depositId, step: null, error: decodeStakeError(e) });
        return false;
      }
    },
    [require]
  );

  const busy = state.step !== null;

  return { state, busy, claim, claimAll, stakeMore, withdraw, withdrawAmount, withdrawAll, reset };
}
