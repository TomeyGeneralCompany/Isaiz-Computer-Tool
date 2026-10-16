"use client";

import Link from "next/link";
import { useCallback, useState } from "react";
import { useWallet } from "@/lib/wallet";
import { useGlobalState, useUserSummary, useLiveReward } from "@/lib/useDashboard";
import { useDeposits } from "@/lib/useDeposits";
import { useOnboardingStatus } from "@/lib/useOnboardingStatus";
import {
  addressUrl,
  dailyRate,
  estimateApr,
  formatPct,
  formatToken,
  formatUsd,
  truncateAddress,
} from "@/lib/format";
import { CONFIG } from "@/lib/config";
import { useTokenSymbol } from "@/lib/tokenSymbol";
import { useTokenPriceUsd } from "@/lib/price";
import { StatCard } from "./StatCard";
import { StakeDialog } from "./StakeDialog";
import { PositionPanel } from "./PositionPanel";
import { RewardSourcesCard } from "./RewardSourcesCard";
import { InfoTooltip } from "./InfoTooltip";

// An address rendered in the shared blue reference-link style, linked to its
// block-explorer page. Falls back to plain text when no explorer is configured.
function ExplorerAddress({ address }: { address: string }) {
  const href = addressUrl(address);
  const style: React.CSSProperties = { wordBreak: "break-all", whiteSpace: "normal" };
  if (!href) {
    return <span className="hl-address" style={style}>{address}</span>;
  }
  return (
    <a className="hl-address hl-contract-link" href={href} target="_blank" rel="noopener noreferrer" style={style}>
      {address}
    </a>
  );
}

// External-link arrow appended to the hero's onboarding step links.
function ExtIcon() {
  return (
    <svg className="hl-ext" width="13" height="13" viewBox="0 0 13 13" fill="none" aria-hidden="true">
      <path
        d="M3 10L10 3M10 3H4.5M10 3v5.5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="hl-label" style={{ display: "block", margin: "0 0 var(--hl-space-5)" }}>
      {children}
    </h2>
  );
}

const grid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: "var(--hl-space-5)",
};

const btnRow: React.CSSProperties = { display: "flex", gap: "var(--hl-space-3)", flexWrap: "wrap" };

const cardHead: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: "var(--hl-space-6)",
  gap: "var(--hl-space-4)",
  flexWrap: "wrap",
};

const posEmpty: React.CSSProperties = { textAlign: "center", padding: "44px 20px" };

export function Dashboard() {
  const {
    address,
    isCorrectChain,
    switchChain,
    addNetwork,
    addToken,
    connect,
    connecting,
    error: walletError,
  } = useWallet();
  const active = address && isCorrectChain ? address : null;
  const symbol = useTokenSymbol();

  const { data: global, error: globalError } = useGlobalState();
  const priceUsd = useTokenPriceUsd();
  const { data: user, reload: reloadUser } = useUserSummary(active);
  const { deposits, reload: reloadDeposits } = useDeposits(active);

  // Multi-position model only: "Add Stake" opens a dialog. Single-position
  // stakes inline via PositionPanel's Stake tab.
  const [dialog, setDialog] = useState<"stake" | null>(null);

  // Single-position: one deposit drives Withdraw/Claim.
  const position = CONFIG.singlePosition ? deposits[0] ?? null : null;

  // Onboarding checklist: each step reads as done once the wallet has
  // demonstrably taken it (holds ETH / holds ZEN / has ZEN staked).
  const { hasEth, hasZen } = useOnboardingStatus(active);
  const hasStaked = (user?.totalStaked ?? 0n) > 0n;

  const liveUnclaimed = useLiveReward(
    user?.totalUnclaimed ?? null,
    global?.rewardRate ?? 0n,
    user?.totalEarningPower ?? 0n,
    global?.totalEarningPower ?? 0n,
    global?.rewardEndTime ?? 0n
  );

  const refresh = useCallback(() => {
    reloadUser();
    reloadDeposits();
  }, [reloadUser, reloadDeposits]);

  return (
    <div className="hl-wrap">
      {/* Hero */}
      <section className="hl-hero">
        <div>
          <h1>
            Stake <em>{symbol}</em>.<br />
            Earn on <em>Horizen</em>.
          </h1>
          <p style={{ color: "var(--hl-grey-text)", fontSize: 16.5, maxWidth: "52ch", marginBottom: "var(--hl-space-6)" }}>
            {symbol} staking is the hub for participation in the {symbol} token economy — with a single
            staking pool that <strong>earns rewards from multiple, independent sources</strong> tied
            to real ecosystem activity.
          </p>
          <div className="hl-chips">
            <span className="hl-chip">
              <span className="hl-plus" aria-hidden="true">+</span> Non-custodial
            </span>
            <span className="hl-chip">
              <span className="hl-plus" aria-hidden="true">+</span> On-chain settlement
            </span>
            <span className="hl-chip">
              <span className="hl-plus" aria-hidden="true">+</span> {symbol} token rewards
            </span>
          </div>
          <div className="hl-ascii-accent" aria-hidden="true">· + · + · + · + · + · + · + · + · + · + · + · +</div>
        </div>

        <aside className="hl-card hl-setup" aria-label="Get set up">
          <span className="hl-label">Add Horizen and {symbol} to your wallet</span>
          <div className="hl-wallet-row">
            <button className="hl-btn hl-btn-ghost hl-btn-sm" onClick={addNetwork}>
              + Network
            </button>
            <button className="hl-btn hl-btn-ghost hl-btn-sm" onClick={addToken}>
              + {symbol}
            </button>
          </div>
          {walletError ? (
            <span className="hl-label" style={{ color: "var(--hl-error)" }}>
              {walletError}
            </span>
          ) : null}
          <ol className="hl-steps">
            <li className={hasEth ? "done" : undefined}>
              {CONFIG.bridgeEthUrl ? (
                <a href={CONFIG.bridgeEthUrl} target="_blank" rel="noopener noreferrer" aria-label="Bridge ETH from Base, opens bridge">
                  Bridge ETH from Base
                  <ExtIcon />
                </a>
              ) : (
                <span>
                  Bridge ETH from Base
                  <ExtIcon />
                </span>
              )}
            </li>
            <li className={hasZen ? "done" : undefined}>
              {CONFIG.bridgeZenUrl ? (
                <a href={CONFIG.bridgeZenUrl} target="_blank" rel="noopener noreferrer" aria-label={`Bridge ${symbol} from Base, opens bridge`}>
                  Bridge {symbol} from Base
                  <ExtIcon />
                </a>
              ) : (
                <span>
                  Bridge {symbol} from Base
                  <ExtIcon />
                </span>
              )}
            </li>
            <li className={hasStaked ? "done" : undefined}>
              <a href="#position">Stake {symbol} on Horizen</a>
            </li>
          </ol>
          <div className="hl-contract-line">
            <span className="hl-label">{symbol} staking contract</span>
            {addressUrl(CONFIG.contractStaker) ? (
              <a className="hl-address hl-contract-link" href={addressUrl(CONFIG.contractStaker)!} target="_blank" rel="noopener noreferrer">
                {truncateAddress(CONFIG.contractStaker)} ↗
              </a>
            ) : (
              <span className="hl-address hl-contract-link">{truncateAddress(CONFIG.contractStaker)}</span>
            )}
          </div>
        </aside>
      </section>

      {/* Protocol stats */}
      {globalError ? (
        <div className="hl-alert hl-alert-error" style={{ marginBottom: "var(--hl-space-12)" }}>
          {globalError}
        </div>
      ) : (
        <div className="hl-stat-band" style={{ marginBottom: "var(--hl-space-12)" }}>
          <div className="hl-stat-cell">
            <span className="hl-label">Global total staked</span>
            <div className="hl-stat-value">{global ? formatToken(global.totalStaked, 6) : "…"}</div>
            <span className="hl-stat-unit">{symbol}</span>
          </div>
          <div className="hl-stat-cell">
            <span className="hl-label">Staked value</span>
            <div className="hl-stat-value">
              {global && priceUsd !== null ? formatUsd(global.totalStaked, priceUsd) : "…"}
            </div>
            <span className="hl-stat-unit">USD</span>
          </div>
          <div className="hl-stat-cell">
            <span className="hl-label">
              Annual rewards rate{" "}
              <InfoTooltip text="ZEN is not a security. Rewards and rewards rate are not guaranteed, and stakers should have no expectation of profit. The ZEN staking program is subject to additional Terms & Conditions." />
            </span>
            <div className="hl-stat-value gold">
              {global ? formatPct(estimateApr(dailyRate(global.rewardRate), global.totalStaked)) : "…"}
            </div>
            <span className="hl-stat-unit">Trailing · variable</span>
          </div>
          <div className="hl-stat-cell">
            <span className="hl-label">
              Daily rewards{" "}
              <InfoTooltip text="ZEN is not a security. Rewards and rewards rate are not guaranteed, and stakers should have no expectation of profit. The ZEN staking program is subject to additional Terms & Conditions." />
            </span>
            <div className="hl-stat-value gold">{global ? formatToken(dailyRate(global.rewardRate), 6) : "…"}</div>
            <span className="hl-stat-unit">{symbol} / day</span>
          </div>
        </div>
      )}

      {/* User position + reward sources */}
      <div id="position" className="hl-lower">
      <div>
      {!address ? (
        <div className="hl-card">
          <div style={cardHead}>
            <h2 className="hl-card-title">My position</h2>
          </div>
          <div style={posEmpty}>
            <p style={{ color: "var(--hl-grey-text)", marginBottom: "var(--hl-space-5)" }}>
              Connect your wallet to see your staking position.
            </p>
            <button className="hl-btn hl-btn-primary" onClick={connect} disabled={connecting}>
              {connecting ? "Connecting…" : "Connect wallet"}
            </button>
          </div>
        </div>
      ) : !isCorrectChain ? (
        <div className="hl-card">
          <div style={cardHead}>
            <h2 className="hl-card-title">My position</h2>
          </div>
          <div className="hl-alert hl-alert-warning" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "var(--hl-space-5)", flexWrap: "wrap" }}>
            <span>Switch to the correct network to view your position.</span>
            <button className="hl-btn hl-btn-ghost hl-btn-sm" onClick={switchChain}>
              Switch network
            </button>
          </div>
        </div>
      ) : CONFIG.singlePosition ? (
        <div className="hl-card">
          <div style={cardHead}>
            <h2 className="hl-card-title">My position</h2>
            <span className="hl-addr-pill">{truncateAddress(address)}</span>
          </div>
          <PositionPanel
            symbol={symbol}
            position={position}
            deposits={deposits}
            stakedBalance={user?.totalStaked ?? null}
            liveUnclaimed={liveUnclaimed}
            onRefresh={refresh}
          />
        </div>
      ) : (
        <>
          <SectionLabel>Your Position:</SectionLabel>
          <div style={{ display: "flex", alignItems: "baseline", gap: "var(--hl-space-3)", marginBottom: "var(--hl-space-6)" }}>
            <span className="hl-label">Wallet address: </span>
            <ExplorerAddress address={address} />
          </div>

          <div style={grid}>
            <StatCard label={`My Staked ${symbol}`} value={user ? formatToken(user.totalStaked, 8) : "…"} unit={symbol} />
            {/* Earning power == staked amount under the identity calculator;
                only meaningful in the multi-deposit model. */}
            <StatCard label="My Earning Power" value={user ? formatToken(user.totalEarningPower) : "…"} />
            <StatCard
              label="Unclaimed Rewards"
              value={liveUnclaimed !== null ? formatToken(liveUnclaimed, 8) : user ? "—" : "…"}
              unit={symbol}
              hint={user?.totalUnclaimed === null ? "Subgraph unavailable" : "Updates live"}
              tone="gold"
            />
          </div>

          {/* Multi-deposit model: management lives on the deposits page. */}
          <div style={{ ...btnRow, marginTop: "var(--hl-space-8)" }}>
            <button className="hl-btn hl-btn-primary" onClick={() => setDialog("stake")}>
              Add Stake
            </button>
            <Link href="/deposits" className="hl-btn hl-btn-ghost">
              Manage Deposits
            </Link>
          </div>
        </>
      )}
      </div>
      <RewardSourcesCard />
      </div>

      {/* Dialogs */}
      {dialog === "stake" && (
        <StakeDialog
          onClose={() => {
            setDialog(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}
