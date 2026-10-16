"use client";

import { useCallback, useState } from "react";
import { formatUnits, parseEther } from "ethers";
import { useWallet } from "@/lib/wallet";
import { useStake } from "@/lib/useStake";
import { useDeposits } from "@/lib/useDeposits";
import { useLearnedDeposits } from "@/lib/learnedDeposits";
import { getReadContracts } from "@/lib/contracts";
import { CONFIG } from "@/lib/config";
import { formatToken } from "@/lib/format";
import { useTokenSymbol } from "@/lib/tokenSymbol";
import { usePolling } from "@/lib/usePolling";

const BALANCE_POLL_MS = 10_000;

// Maps each in-progress phase to its step number + label. The stake steps shift
// from 3/4 & 4/4 (approval required) down to 1/2 & 2/2 when the allowance
// already covers the amount, so the count always matches `totalSteps`.
function stepInfo(
  status: string,
  totalSteps: number
): { n: number; label: string } | null {
  const withApproval = totalSteps === 4;
  switch (status) {
    case "approve-wallet":
      return { n: 1, label: "Approve token spending in your wallet" };
    case "approve-pending":
      return { n: 2, label: "Waiting for the approval to confirm" };
    case "stake-wallet":
      return { n: withApproval ? 3 : 1, label: "Confirm the stake in your wallet" };
    case "stake-pending":
      return { n: withApproval ? 4 : 2, label: "Waiting for the stake to confirm" };
    default:
      return null;
  }
}

// The stake form, chrome-free so it can live inside a dialog. Handles
// create-or-increase (single-position); staking always uses approve + stake.
export function StakeForm({ onSuccess, onCancel }: { onSuccess?: () => void; onCancel?: () => void }) {
  const { address, isCorrectChain } = useWallet();
  const { status, error, totalSteps, stake, reset } = useStake();
  const { add: learnDeposit } = useLearnedDeposits();

  const active = address && isCorrectChain ? address : null;
  const { deposits } = useDeposits(active);
  const existing = CONFIG.singlePosition && deposits.length > 0 ? deposits[0] : null;
  const isIncrease = !!existing;

  const [amount, setAmount] = useState("");
  const [balance, setBalance] = useState<bigint | null>(null);
  const symbol = useTokenSymbol();

  const loadBalance = useCallback(async () => {
    if (!address) {
      setBalance(null);
      return;
    }
    try {
      const { token } = getReadContracts();
      const b = (await token.balanceOf(address)) as bigint;
      setBalance(b);
    } catch {
      // keep the last known balance on a transient read failure
    }
  }, [address]);

  usePolling(loadBalance, BALANCE_POLL_MS);

  const step = stepInfo(status, totalSteps);
  const busy = step !== null;

  let amountError: string | null = null;
  if (amount) {
    try {
      const parsed = parseEther(amount);
      if (parsed <= 0n) amountError = "Enter an amount greater than zero.";
      else if (balance !== null && parsed > balance) amountError = "Amount exceeds your balance.";
    } catch {
      amountError = "Invalid amount.";
    }
  }
  const canSubmit = !!active && !!amount && !amountError && !busy;

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    const outcome = await stake(amount, existing?.depositId ?? null);
    if (outcome.ok) {
      if (outcome.depositId != null && address) learnDeposit(address, outcome.depositId);
      loadBalance();
      onSuccess?.();
    }
  };

  return (
    <form onSubmit={onSubmit}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "var(--hl-space-2)" }}>
        <label className="hl-label" htmlFor="stake-amount">Amount</label>
        {balance !== null && (
          <button
            type="button"
            className="hl-label hl-contract-link"
            style={{ background: "none", border: 0, cursor: "pointer" }}
            onClick={() => setAmount(formatUnits(balance, 18))}
          >
            Balance: {formatToken(balance)} {symbol} · Max
          </button>
        )}
      </div>

      <input
        id="stake-amount"
        className="hl-input"
        inputMode="decimal"
        placeholder="0.0"
        value={amount}
        onChange={(e) => {
          setAmount(e.target.value.replace(/[^0-9.]/g, ""));
          if (status !== "idle") reset();
        }}
        disabled={busy}
        autoFocus
      />
      {amountError && <p style={{ color: "var(--hl-error)", fontSize: 13, marginTop: 8 }}>{amountError}</p>}

      <div style={{ display: "flex", gap: "var(--hl-space-4)", marginTop: "var(--hl-space-8)" }}>
        {onCancel && (
          <button type="button" className="hl-btn hl-btn-ghost" style={{ flex: 1 }} onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
        <button type="submit" className="hl-btn hl-btn-primary" style={{ flex: 1 }} disabled={!canSubmit}>
          {busy ? "Processing…" : isIncrease ? "Add to Stake" : "Stake"}
        </button>
      </div>

      {step && (
        <div className="hl-alert hl-alert-warning" style={{ marginTop: "var(--hl-space-5)" }}>
          Step {step.n}/{totalSteps}: {step.label}…
        </div>
      )}
      {status === "error" && error && (
        <div className="hl-alert hl-alert-error" style={{ marginTop: "var(--hl-space-5)" }}>
          {error}
        </div>
      )}
    </form>
  );
}
