"use client";

import { useEffect, useState } from "react";
import { formatUnits, parseEther } from "ethers";
import { formatToken } from "@/lib/format";

export interface ActionModalProps {
  mode: "stakeMore" | "withdraw";
  depositId: bigint;
  max: bigint; // wallet balance (stakeMore) or deposit balance (withdraw)
  maxLabel: string; // e.g. "Wallet" or "Staked"
  unclaimed?: bigint; // withdraw only — to offer claiming rewards too
  symbol: string;
  busy: boolean;
  phaseLabel: string | null;
  error: string | null;
  onConfirm: (amount: bigint, claimRewards: boolean) => void;
  onClose: () => void;
}

export function ActionModal({
  mode,
  depositId,
  max,
  maxLabel,
  unclaimed = 0n,
  symbol,
  busy,
  phaseLabel,
  error,
  onConfirm,
  onClose,
}: ActionModalProps) {
  const [amount, setAmount] = useState("");
  const [claimRewards, setClaimRewards] = useState(unclaimed > 0n);

  // ESC to close (when not busy)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const title = mode === "stakeMore" ? "Stake More" : "Withdraw";

  let amountError: string | null = null;
  if (amount) {
    try {
      const parsed = parseEther(amount);
      if (parsed <= 0n) amountError = "Enter an amount greater than zero.";
      else if (parsed > max) amountError = `Amount exceeds ${maxLabel.toLowerCase()} balance.`;
    } catch {
      amountError = "Invalid amount.";
    }
  }
  const valid = !!amount && !amountError;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (valid) onConfirm(parseEther(amount), mode === "withdraw" && claimRewards);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`${title} deposit ${depositId}`}
      onClick={() => !busy && onClose()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(4, 23, 66, 0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        zIndex: 400,
      }}
    >
      <div
        className="hl-card"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 440, width: "100%" }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <h2 style={{ fontSize: 24 }}>{title}</h2>
        </div>

        <form onSubmit={submit} style={{ marginTop: "var(--hl-space-6)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "var(--hl-space-2)" }}>
            <label className="hl-label" htmlFor="amt">Amount</label>
            <button
              type="button"
              className="hl-label hl-contract-link"
              style={{ background: "none", border: 0, cursor: "pointer" }}
              onClick={() => setAmount(formatUnits(max, 18))}
            >
              {maxLabel}: {formatToken(max)} {symbol} · Max
            </button>
          </div>
          <input
            id="amt"
            className="hl-input"
            inputMode="decimal"
            placeholder="0.0"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
            disabled={busy}
            autoFocus
          />
          {amountError && (
            <p style={{ color: "var(--hl-error)", fontSize: 13, marginTop: 8 }}>{amountError}</p>
          )}

          {mode === "withdraw" && unclaimed > 0n && (
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginTop: "var(--hl-space-5)",
                fontSize: 14,
                color: "var(--hl-grey-text)",
              }}
            >
              <input
                type="checkbox"
                checked={claimRewards}
                onChange={(e) => setClaimRewards(e.target.checked)}
                disabled={busy}
                style={{ accentColor: "var(--hl-gold)" }}
              />
              Claim pending rewards also (separate tx)
            </label>
          )}

          {busy && phaseLabel && (
            <div className="hl-alert hl-alert-warning" style={{ marginTop: "var(--hl-space-5)" }}>
              {phaseLabel}…
            </div>
          )}
          {error && (
            <div className="hl-alert hl-alert-error" style={{ marginTop: "var(--hl-space-5)" }}>
              {error}
            </div>
          )}

          <div style={{ display: "flex", gap: "var(--hl-space-4)", marginTop: "var(--hl-space-8)" }}>
            <button type="button" className="hl-btn hl-btn-ghost" style={{ flex: 1 }} onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="hl-btn hl-btn-primary" style={{ flex: 1 }} disabled={!valid || busy}>
              {busy ? "Processing…" : title}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
