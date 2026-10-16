"use client";

import { useCallback, useState } from "react";
import { formatUnits, parseEther } from "ethers";
import { useWallet } from "@/lib/wallet";
import { useStake } from "@/lib/useStake";
import { useDepositActions, actionStepLabel } from "@/lib/useDepositActions";
import { useLearnedDeposits } from "@/lib/learnedDeposits";
import { getReadContracts } from "@/lib/contracts";
import { formatToken } from "@/lib/format";
import type { DepositDetail } from "@/lib/useDeposits";
import { usePolling } from "@/lib/usePolling";

const BALANCE_POLL_MS = 10_000;

type Tab = "stake" | "withdraw" | "claim";

// Maps each in-progress stake phase to its step number + label. Steps shift
// from 3/4 & 4/4 (approval required) down to 1/2 & 2/2 when the allowance
// already covers the amount, so the count always matches `totalSteps`.
function stakeStepInfo(status: string, totalSteps: number): { n: number; label: string } | null {
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

const posStat: React.CSSProperties = {
  background: "var(--hl-grey-light)",
  borderRadius: "var(--hl-radius-sm)",
  padding: 20,
};

// Single-position dashboard card: display-only Staked/Unclaimed cells plus an
// inline Stake / Withdraw / Claim tab switcher (no dialogs), matching the
// redesigned mockup. Multi-deposit management stays dialog-based on /deposits.
// The outer "My position" card and header live in Dashboard, shared across
// the connect / wrong-network / connected states.
export function PositionPanel({
  symbol,
  position,
  deposits,
  stakedBalance,
  liveUnclaimed,
  onRefresh,
}: {
  symbol: string;
  position: DepositDetail | null;
  // Every deposit the wallet holds. Normally just [position] (or empty), but
  // staking directly against the contract (bypassing stakeMore) can leave
  // more than one — Withdraw/Claim act across all of them.
  deposits: DepositDetail[];
  // Total staked from getDepositorSummary — a pure on-chain aggregate that
  // needs no deposit-ID lookup, so it stays correct even when the subgraph
  // (and the learned-deposits cache) hasn't caught up with a just-created
  // deposit yet. Falls back to `position` while it's still loading.
  stakedBalance: bigint | null;
  liveUnclaimed: bigint | null;
  onRefresh: () => void;
}) {
  const [tab, setTab] = useState<Tab>("stake");
  const unclaimedDisplay = liveUnclaimed ?? position?.unclaimedRewards ?? null;

  return (
    <>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
          gap: "var(--hl-space-4)",
          marginBottom: "var(--hl-space-8)",
        }}
      >
        <div style={posStat}>
          <div className="hl-label" style={{ marginBottom: 12 }}>
            Staked
          </div>
          <div style={{ fontSize: 26, fontWeight: 700, lineHeight: 1, marginBottom: 6, color: "var(--hl-navy-hover)" }}>
            {formatToken(stakedBalance ?? position?.balance ?? 0n)}
          </div>
          <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)" }}>{symbol}</span>
        </div>
        <div style={posStat}>
          <div className="hl-label" style={{ marginBottom: 12 }}>
            Unclaimed rewards
          </div>
          <div style={{ fontSize: 26, fontWeight: 700, lineHeight: 1, marginBottom: 6, color: "var(--hl-gold-bright)" }}>
            {unclaimedDisplay !== null ? formatToken(unclaimedDisplay, 6) : "—"}
          </div>
          <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)" }}>{symbol}</span>
        </div>
      </div>

      <div className="hl-tabs" role="tablist" aria-label="Staking actions">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "stake"}
          className={`hl-tab${tab === "stake" ? " active" : ""}`}
          onClick={() => setTab("stake")}
        >
          Stake
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "withdraw"}
          className={`hl-tab${tab === "withdraw" ? " active" : ""}`}
          onClick={() => setTab("withdraw")}
        >
          Withdraw
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "claim"}
          className={`hl-tab${tab === "claim" ? " active" : ""}`}
          onClick={() => setTab("claim")}
        >
          Claim
        </button>
      </div>

      <div style={{ marginTop: "var(--hl-space-6)" }}>
        {tab === "stake" && (
          <StakePanel symbol={symbol} position={position} stakedBalance={stakedBalance} onDone={onRefresh} />
        )}
        {tab === "withdraw" && <WithdrawPanel symbol={symbol} deposits={deposits} onDone={onRefresh} />}
        {tab === "claim" && (
          <ClaimPanel symbol={symbol} deposits={deposits} unclaimedDisplay={unclaimedDisplay} onDone={onRefresh} />
        )}
      </div>
    </>
  );
}

function StakePanel({
  symbol,
  position,
  stakedBalance,
  onDone,
}: {
  symbol: string;
  position: DepositDetail | null;
  // Chain aggregate (getDepositorSummary) — always correct, unlike `position`
  // which depends on the subgraph/learned-deposits cache having caught up
  // with the deposit id. Used to detect that mismatch: if this shows an
  // existing stake but `position` is still null, we don't yet know the
  // deposit id and must not fall through to creating a second deposit.
  stakedBalance: bigint | null;
  onDone: () => void;
}) {
  const { address } = useWallet();
  const { status, error, totalSteps, stake, reset } = useStake();
  const { add: learnDeposit } = useLearnedDeposits();
  const [amount, setAmount] = useState("");
  const [balance, setBalance] = useState<bigint | null>(null);

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

  const step = stakeStepInfo(status, totalSteps);
  const busy = step !== null;

  // Single-position rule: once the user has a stake, every stake action must
  // be stakeMore, never a fresh stake — except the very first one. `position`
  // (subgraph/learned-cache derived) is what supplies the deposit id needed
  // for stakeMore; `stakedBalance` (chain aggregate) is what's always right
  // about whether a stake already exists. When they disagree — stake > 0 but
  // no resolved deposit id yet — block submission instead of defaulting to
  // "create a new deposit", which would silently open a second position.
  const resolvingExisting = (stakedBalance ?? 0n) > 0n && !position;

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
  const canSubmit = !!address && !!amount && !amountError && !busy && !resolvingExisting;

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    const outcome = await stake(amount, position?.depositId ?? null);
    if (outcome.ok) {
      if (outcome.depositId != null && address) learnDeposit(address, outcome.depositId);
      setAmount("");
      reset();
      onDone();
      loadBalance();
    }
  };

  return (
    <form onSubmit={onSubmit}>
      <div className="hl-amount-box">
        <input
          inputMode="decimal"
          placeholder="0.00"
          aria-label={`Amount of ${symbol} to stake`}
          value={amount}
          onChange={(e) => {
            setAmount(e.target.value.replace(/[^0-9.]/g, ""));
            if (status !== "idle") reset();
          }}
          disabled={busy}
          autoFocus
        />
        <div style={{ display: "flex", alignItems: "center", gap: 12, flex: "none" }}>
          {balance !== null && (
            <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)", whiteSpace: "nowrap" }}>
              Wallet {formatToken(balance)} {symbol}
            </span>
          )}
          <button type="button" className="hl-max-btn" onClick={() => balance !== null && setAmount(formatUnits(balance, 18))}>
            MAX
          </button>
        </div>
      </div>
      {amountError && <p style={{ color: "var(--hl-error)", fontSize: 13, marginTop: 8 }}>{amountError}</p>}

      <button type="submit" className="hl-btn hl-btn-primary" style={{ width: "100%", marginTop: "var(--hl-space-5)" }} disabled={!canSubmit}>
        {busy ? "Processing…" : position || resolvingExisting ? "Add to stake" : "Stake " + symbol}
      </button>
      <p style={{ fontSize: 12.5, color: "var(--hl-grey-text)", textAlign: "center", marginTop: "var(--hl-space-4)" }}>
        Rewards accrue continuously and never expire.
      </p>

      {resolvingExisting && !step && (
        <div className="hl-alert hl-alert-warning" style={{ marginTop: "var(--hl-space-5)" }}>
          Resolving your existing deposit, please wait…
        </div>
      )}
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

function WithdrawPanel({
  symbol,
  deposits,
  onDone,
}: {
  symbol: string;
  deposits: DepositDetail[];
  onDone: () => void;
}) {
  const actions = useDepositActions();
  const [amount, setAmount] = useState("");
  const [claimRewards, setClaimRewards] = useState(deposits.some((d) => d.unclaimedRewards > 0n));
  const hasPosition = deposits.length > 0;
  // Aggregate cap across every deposit. When more than one deposit exists
  // (e.g. staked directly on the contract, bypassing stakeMore), the amount
  // entered here isn't tied to a single deposit — it's drained starting from
  // the largest one, cascading into the next largest as needed.
  const max = deposits.reduce((a, d) => a + d.balance, 0n);
  const stepLabel = actionStepLabel(actions.state);

  let amountError: string | null = null;
  if (amount) {
    try {
      const parsed = parseEther(amount);
      if (parsed <= 0n) amountError = "Enter an amount greater than zero.";
      else if (parsed > max) amountError = "Amount exceeds staked balance.";
    } catch {
      amountError = "Invalid amount.";
    }
  }
  const canSubmit = hasPosition && !!amount && !amountError && !actions.busy;

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    const ok = await actions.withdrawAmount(deposits, parseEther(amount), claimRewards);
    if (ok) {
      setAmount("");
      onDone();
    }
  };

  return (
    <form onSubmit={onSubmit}>
      <div className="hl-amount-box">
        <input
          inputMode="decimal"
          placeholder="0.00"
          aria-label={`Amount of ${symbol} to withdraw`}
          value={amount}
          onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
          disabled={actions.busy || !hasPosition}
          autoFocus
        />
        <div style={{ display: "flex", alignItems: "center", gap: 12, flex: "none" }}>
          <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)", whiteSpace: "nowrap" }}>
            Staked {formatToken(max)} {symbol}
          </span>
          <button type="button" className="hl-max-btn" onClick={() => setAmount(formatUnits(max, 18))} disabled={!hasPosition}>
            MAX
          </button>
        </div>
      </div>
      {amountError && <p style={{ color: "var(--hl-error)", fontSize: 13, marginTop: 8 }}>{amountError}</p>}

      {deposits.some((d) => d.unclaimedRewards > 0n) && (
        <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: "var(--hl-space-4)", fontSize: 14, color: "var(--hl-grey-text)" }}>
          <input
            type="checkbox"
            checked={claimRewards}
            onChange={(e) => setClaimRewards(e.target.checked)}
            disabled={actions.busy}
            style={{ accentColor: "var(--hl-gold)" }}
          />
          Claim pending rewards too (separate tx)
        </label>
      )}

      <button type="submit" className="hl-btn hl-btn-primary" style={{ width: "100%", marginTop: "var(--hl-space-5)" }} disabled={!canSubmit}>
        {actions.busy ? "Processing…" : "Withdraw"}
      </button>
      <p style={{ fontSize: 12.5, color: "var(--hl-grey-text)", textAlign: "center", marginTop: "var(--hl-space-4)" }}>
        Your principal is never locked — withdraw whenever you want.
      </p>

      {stepLabel && (
        <div className="hl-alert hl-alert-warning" style={{ marginTop: "var(--hl-space-5)" }}>
          {stepLabel}…
        </div>
      )}
      {actions.state.error && (
        <div className="hl-alert hl-alert-error" style={{ marginTop: "var(--hl-space-5)" }}>
          {actions.state.error}
        </div>
      )}
    </form>
  );
}

function ClaimPanel({
  symbol,
  deposits,
  unclaimedDisplay,
  onDone,
}: {
  symbol: string;
  deposits: DepositDetail[];
  unclaimedDisplay: bigint | null;
  onDone: () => void;
}) {
  const actions = useDepositActions();
  const stepLabel = actionStepLabel(actions.state);
  const canClaim = !actions.busy && deposits.some((d) => d.unclaimedRewards > 0n);

  const onClaim = async () => {
    const ok = await actions.claimAll(deposits);
    if (ok) onDone();
  };

  return (
    <div>
      <div className="hl-claim-box">
        <div className="hl-label" style={{ marginBottom: 12 }}>
          Rewards ready to claim
        </div>
        <div className="hl-claim-amount">{unclaimedDisplay !== null ? formatToken(unclaimedDisplay, 6) : "—"}</div>
        <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)", display: "block", marginTop: 8 }}>
          {symbol}
        </span>
      </div>

      <button className="hl-btn hl-btn-gold" style={{ width: "100%", marginTop: "var(--hl-space-5)" }} onClick={onClaim} disabled={!canClaim}>
        {actions.busy ? "Claiming…" : "Claim rewards"}
      </button>
      <p style={{ fontSize: 12.5, color: "var(--hl-grey-text)", textAlign: "center", marginTop: "var(--hl-space-4)" }}>
        Claiming sends rewards to your connected wallet. Unclaimed rewards keep accruing.
      </p>

      {stepLabel && (
        <div className="hl-alert hl-alert-warning" style={{ marginTop: "var(--hl-space-5)" }}>
          {stepLabel}…
        </div>
      )}
      {actions.state.error && (
        <div className="hl-alert hl-alert-error" style={{ marginTop: "var(--hl-space-5)" }}>
          {actions.state.error}
        </div>
      )}
    </div>
  );
}
