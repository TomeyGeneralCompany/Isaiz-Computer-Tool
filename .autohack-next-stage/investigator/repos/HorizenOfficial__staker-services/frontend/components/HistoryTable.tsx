"use client";

import { useWallet } from "@/lib/wallet";
import { useActivity } from "@/lib/useActivity";
import { type ActivityType } from "@/lib/subgraph";
import { formatToken } from "@/lib/format";
import { CONFIG } from "@/lib/config";
import { useTokenSymbol } from "@/lib/tokenSymbol";

function txUrl(hash: string): string | null {
  return CONFIG.explorerUrl ? `${CONFIG.explorerUrl.replace(/\/+$/, "")}/tx/${hash}` : null;
}

function shortHash(hash: string): string {
  return `${hash.slice(0, 10)}…${hash.slice(-8)}`;
}

const TYPE_META: Record<ActivityType, { label: string; color: string; bg: string }> = {
  stake: { label: "Stake", color: "#ffffff", bg: "var(--hl-bright-blue)" },
  withdraw: { label: "Withdraw", color: "var(--hl-grey-text)", bg: "var(--hl-grey-light)" },
  claim: { label: "Claim", color: "var(--hl-deep-blue)", bg: "var(--hl-sunrise-light)" },
};

function TypeBadge({ type }: { type: ActivityType }) {
  const m = TYPE_META[type];
  return (
    <span
      style={{
        fontSize: 11.5,
        fontWeight: 700,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        borderRadius: 6,
        padding: "5px 11px",
        display: "inline-block",
        color: m.color,
        background: m.bg,
      }}
    >
      {m.label}
    </span>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "var(--hl-space-5)",
  borderBottom: "2px solid var(--hl-sunrise)",
};
const td: React.CSSProperties = { padding: "var(--hl-space-5)", fontSize: 14.5, fontWeight: 600, color: "var(--hl-navy)" };

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="hl-card" style={{ textAlign: "center", padding: "var(--hl-space-12)", color: "var(--hl-grey-text)" }}>
      {children}
    </div>
  );
}

export function HistoryTable() {
  const { address, isCorrectChain, switchChain } = useWallet();
  const active = address && isCorrectChain ? address : null;
  const { items, loading, error, canLoadMore, loadMore } = useActivity(active);
  const symbol = useTokenSymbol();

  return (
    <div className="hl-wrap">
      <div className="hl-page-head">
        <h1>
          Your <em>history</em>.
        </h1>
        <p className="hl-page-sub">All staking operations for the connected address.</p>
      </div>

      {!address ? (
        <Empty>
          <p>Connect your wallet to view your history.</p>
        </Empty>
      ) : !isCorrectChain ? (
        <div className="hl-alert hl-alert-warning" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "var(--hl-space-5)", flexWrap: "wrap" }}>
          <span>Switch to the correct network to view your history.</span>
          <button className="hl-btn hl-btn-ghost hl-btn-sm" onClick={switchChain}>
            Switch network
          </button>
        </div>
      ) : error ? (
        <div className="hl-alert hl-alert-error">{error}</div>
      ) : loading && items.length === 0 ? (
        <Empty>
          <p>Loading history…</p>
        </Empty>
      ) : items.length === 0 ? (
        <Empty>
          <p>No activity yet.</p>
        </Empty>
      ) : (
        <>
          <div className="hl-card" style={{ padding: 0, overflowX: "auto" }}>
            <table className="hl-history-table" style={{ width: "100%", borderCollapse: "collapse", minWidth: 640 }}>
              <thead>
                <tr>
                  <th className="hl-label" style={th}>Type</th>
                  <th className="hl-label" style={{ ...th, textAlign: "right" }}>Amount</th>
                  <th className="hl-label" style={th}>Date</th>
                  <th className="hl-label" style={th}>Tx</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <tr key={`${it.txHash}-${it.type}-${it.depositId}`} style={{ borderTop: "1px solid var(--hl-grey)" }}>
                    <td data-label="Type" style={td}><TypeBadge type={it.type} /></td>
                    <td data-label="Amount" style={{ ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                      {formatToken(it.amount, 8)} {symbol}
                    </td>
                    <td data-label="Date" style={{ ...td, color: "var(--hl-grey-text)", fontWeight: 400, fontSize: 14 }}>
                      {new Date(it.timestamp * 1000).toLocaleString()}
                    </td>
                    <td data-label="Tx" style={td}>
                      {txUrl(it.txHash) ? (
                        <a
                          href={txUrl(it.txHash)!}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="hl-address hl-contract-link"
                          style={{ whiteSpace: "nowrap" }}
                        >
                          {shortHash(it.txHash)}
                        </a>
                      ) : (
                        <span className="hl-address" style={{ whiteSpace: "nowrap" }}>{shortHash(it.txHash)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {canLoadMore && (
            <div style={{ marginTop: "var(--hl-space-6)", textAlign: "center" }}>
              <button className="hl-btn hl-btn-ghost hl-btn-sm" onClick={loadMore} disabled={loading}>
                {loading ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
