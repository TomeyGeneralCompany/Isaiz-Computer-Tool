"use client";

import Link from "next/link";
import { useCallback, useState } from "react";
import { formatUnits } from "ethers";
import { useWallet } from "@/lib/wallet";
import { useDeposits, type DepositDetail } from "@/lib/useDeposits";
import { useDepositActions, actionStepLabel } from "@/lib/useDepositActions";
import { getReadContracts } from "@/lib/contracts";
import { CONFIG } from "@/lib/config";
import { formatToken } from "@/lib/format";
import { useTokenSymbol } from "@/lib/tokenSymbol";
import { usePolling } from "@/lib/usePolling";
import { ActionModal } from "./ActionModal";

const BALANCE_POLL_MS = 10_000;

export function DepositsTable() {
  const { address, isCorrectChain } = useWallet();
  const active = address && isCorrectChain ? address : null;
  const { deposits, loading, error, subgraphDown, reload } = useDeposits(active);
  const actions = useDepositActions();

  const [walletBalance, setWalletBalance] = useState<bigint>(0n);
  const symbol = useTokenSymbol();
  const [modal, setModal] = useState<{ mode: "stakeMore" | "withdraw"; deposit: DepositDetail } | null>(null);

  const loadWallet = useCallback(async () => {
    if (!active) {
      setWalletBalance(0n);
      return;
    }
    try {
      const { token } = getReadContracts();
      const b = (await token.balanceOf(active)) as bigint;
      setWalletBalance(b);
    } catch {
      // keep the last known balance on a transient read failure
    }
  }, [active]);

  usePolling(loadWallet, BALANCE_POLL_MS);

  // refresh data after any action finishes (state returns to idle)
  const afterAction = useCallback(async () => {
    await Promise.all([reload(), loadWallet()]);
  }, [reload, loadWallet]);

  const totalUnclaimed = deposits.reduce((a, d) => a + d.unclaimedRewards, 0n);
  const hasClaimable = totalUnclaimed > 0n;
  const totalStaked = deposits.reduce((a, d) => a + d.balance, 0n);
  const hasWithdrawable = totalStaked > 0n;

  const stepLabel = actionStepLabel(actions.state);

  // Single-position mode: present one aggregated position when the user has at
  // most one deposit. >1 deposits (legacy / created elsewhere) falls back to the table.
  const singleView = CONFIG.singlePosition && deposits.length <= 1;

  if (!address) {
    return (
      <Empty>
        <p>Connect your wallet to view your deposits.</p>
      </Empty>
    );
  }
  if (!isCorrectChain) {
    return <div className="hl-alert hl-alert-warning">Switch to the correct network to view your deposits.</div>;
  }

  return (
    <div style={{ maxWidth: 880, width: "100%", padding: "0 clamp(20px, 4vw, 28px)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "var(--hl-space-8)" }}>
        <div>
          <h1 style={{ fontSize: 45 }}>{CONFIG.singlePosition ? "My Stake" : "My Deposits"}</h1>
          <p style={{ color: "var(--hl-grey-text)", margin: "var(--hl-space-2) 0 0" }}>
            {CONFIG.singlePosition ? "Manage your staking position." : "Manage your staking positions."}
          </p>
        </div>
        {/* Claim All / Withdraw All only in the multi-deposit table; the
            single-position card has its own Claim / Withdraw. */}
        {!singleView && (
          <div style={{ display: "flex", gap: "var(--hl-space-3)" }}>
            <button
              className="hl-btn hl-btn-ghost hl-btn-sm"
              disabled={!hasWithdrawable || actions.busy}
              onClick={async () => {
                const ok = await actions.withdrawAll(deposits, false);
                if (ok) afterAction();
              }}
            >
              {actions.state.kind === "withdrawAll" ? "Withdrawing…" : `Withdraw All${hasWithdrawable ? ` (${formatToken(totalStaked)})` : ""}`}
            </button>
            <button
              className="hl-btn hl-btn-primary hl-btn-sm"
              disabled={!hasClaimable || actions.busy}
              onClick={async () => {
                const ok = await actions.claimAll(deposits);
                if (ok) afterAction();
              }}
            >
              {actions.state.kind === "claimAll" ? "Claiming…" : `Claim All${hasClaimable ? ` (${formatToken(totalUnclaimed)})` : ""}`}
            </button>
          </div>
        )}
      </div>

      {subgraphDown && (
        <div className="hl-alert hl-alert-error" style={{ marginBottom: "var(--hl-space-5)" }}>
          {error ?? "Subgraph unavailable — cannot list deposits right now."}
        </div>
      )}

      {actions.state.error && !modal && (
        <div className="hl-alert hl-alert-error" style={{ marginBottom: "var(--hl-space-5)" }}>
          {actions.state.error}
        </div>
      )}

      {/* Progress for inline claim / claim-all (modals show their own). */}
      {actions.busy && !modal && stepLabel && (
        <div className="hl-alert hl-alert-warning" style={{ marginBottom: "var(--hl-space-5)" }}>
          {stepLabel}…
        </div>
      )}

      {loading && deposits.length === 0 ? (
        <Empty><p>Loading deposits…</p></Empty>
      ) : deposits.length === 0 && !subgraphDown ? (
        <Empty>
          <p style={{ marginBottom: "var(--hl-space-6)" }}>You have no active deposits yet.</p>
          <Link href="/stake" className="hl-btn hl-btn-primary">Stake {symbol}</Link>
        </Empty>
      ) : singleView && deposits.length === 1 ? (
        <PositionCard
          deposit={deposits[0]}
          symbol={symbol}
          busy={actions.busy}
          claiming={actions.busy && actions.state.kind === "claim"}
          onClaim={async () => {
            const ok = await actions.claim(deposits[0].depositId);
            if (ok) afterAction();
          }}
          onWithdraw={() => setModal({ mode: "withdraw", deposit: deposits[0] })}
        />
      ) : (
        <div className="hl-card" style={{ padding: 0, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 720 }}>
            <thead>
              <tr>
                <Th>Deposit</Th>
                <Th align="right">Staked</Th>
                <Th align="right">Earning Power</Th>
                <Th align="right">Unclaimed</Th>
                <Th align="right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {deposits.map((d) => {
                const rowBusy = actions.busy && actions.state.target === d.depositId;
                return (
                  <tr key={d.depositId.toString()} style={{ borderTop: "1px solid var(--hl-grey)" }}>
                    <Td><span className="hl-mono">#{d.depositId.toString()}</span></Td>
                    <Td align="right">{formatToken(d.balance)} {symbol}</Td>
                    <Td align="right">{formatToken(d.earningPower)}</Td>
                    <Td align="right">{formatToken(d.unclaimedRewards, 6)} {symbol}</Td>
                    <Td align="right">
                      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                        <RowBtn
                          disabled={actions.busy}
                          onClick={() => setModal({ mode: "stakeMore", deposit: d })}
                        >
                          Stake more
                        </RowBtn>
                        <RowBtn
                          disabled={actions.busy || d.unclaimedRewards === 0n}
                          onClick={async () => {
                            const ok = await actions.claim(d.depositId);
                            if (ok) afterAction();
                          }}
                        >
                          {rowBusy && actions.state.kind === "claim" ? "Claiming…" : "Claim"}
                        </RowBtn>
                        <RowBtn
                          disabled={actions.busy}
                          onClick={() => setModal({ mode: "withdraw", deposit: d })}
                        >
                          Withdraw
                        </RowBtn>
                      </div>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {modal && (
        <ActionModal
          mode={modal.mode}
          depositId={modal.deposit.depositId}
          max={modal.mode === "stakeMore" ? walletBalance : modal.deposit.balance}
          maxLabel={modal.mode === "stakeMore" ? "Wallet" : "Staked"}
          unclaimed={modal.deposit.unclaimedRewards}
          symbol={symbol}
          busy={actions.busy}
          phaseLabel={stepLabel}
          error={actions.state.error}
          onClose={() => {
            if (!actions.busy) {
              actions.reset();
              setModal(null);
            }
          }}
          onConfirm={async (amount, claimRewards) => {
            const ok =
              modal.mode === "stakeMore"
                ? // stakeMore takes a decimal string; convert the parsed bigint back
                  await actions.stakeMore(modal.deposit.depositId, formatUnits(amount, 18))
                : await actions.withdraw(modal.deposit.depositId, amount, claimRewards);
            if (ok) {
              setModal(null);
              afterAction();
            }
          }}
        />
      )}
    </div>
  );
}

function PositionCard({
  deposit,
  symbol,
  busy,
  claiming,
  onClaim,
  onWithdraw,
}: {
  deposit: DepositDetail;
  symbol: string;
  busy: boolean;
  claiming: boolean;
  onClaim: () => void;
  onWithdraw: () => void;
}) {
  const hasRewards = deposit.unclaimedRewards > 0n;
  const stat = (label: string, value: string, unit?: string) => (
    <div>
      <div className="hl-label" style={{ marginBottom: 6 }}>{label}</div>
      <div className="hl-mono" style={{ fontSize: 24, fontWeight: 600 }}>
        {value}
        {unit && <span style={{ fontSize: 13, color: "var(--hl-grey-text)", marginLeft: 6 }}>{unit}</span>}
      </div>
    </div>
  );

  return (
    <div className="hl-card">
      <span className="hl-label">Position</span>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: "var(--hl-space-6)",
          margin: "var(--hl-space-6) 0 var(--hl-space-8)",
        }}
      >
        {stat("Staked", formatToken(deposit.balance), symbol)}
        {stat("Unclaimed", formatToken(deposit.unclaimedRewards, 6), symbol)}
      </div>

      <div style={{ display: "flex", gap: "var(--hl-space-4)", flexWrap: "wrap" }}>
        <Link href="/stake" className="hl-btn hl-btn-primary hl-btn-sm">
          Add to Stake
        </Link>
        <button className="hl-btn hl-btn-ghost hl-btn-sm" disabled={busy || !hasRewards} onClick={onClaim}>
          {claiming ? "Claiming…" : "Claim"}
        </button>
        <button className="hl-btn hl-btn-ghost hl-btn-sm" disabled={busy} onClick={onWithdraw}>
          Withdraw
        </button>
      </div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="hl-card" style={{ textAlign: "center", padding: "var(--hl-space-12)", color: "var(--hl-grey-text)" }}>
      {children}
    </div>
  );
}

function Th({ children, align = "left" }: { children: React.ReactNode; align?: "left" | "right" }) {
  return (
    <th
      className="hl-label"
      style={{ textAlign: align, padding: "var(--hl-space-5)", borderBottom: "2px solid var(--hl-gold)" }}
    >
      {children}
    </th>
  );
}

function Td({ children, align = "left" }: { children: React.ReactNode; align?: "left" | "right" }) {
  return (
    <td className="hl-mono" style={{ textAlign: align, padding: "var(--hl-space-5)", fontSize: 14 }}>
      {children}
    </td>
  );
}

function RowBtn({ children, onClick, disabled }: { children: React.ReactNode; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="hl-mono"
      style={{
        fontSize: 11,
        letterSpacing: 1,
        textTransform: "uppercase",
        padding: "8px 12px",
        border: "1px solid var(--hl-navy)",
        background: "var(--hl-panel)",
        color: "var(--hl-navy)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {children}
    </button>
  );
}
