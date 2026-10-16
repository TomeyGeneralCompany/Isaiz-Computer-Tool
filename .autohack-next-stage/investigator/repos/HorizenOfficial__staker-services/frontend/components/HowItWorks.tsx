"use client";

import { CONFIG } from "@/lib/config";
import { addressUrl, tokenUrl, truncateAddress } from "@/lib/format";
import { useTokenSymbol } from "@/lib/tokenSymbol";

const CONTRACTS_SOURCE_URL = "https://github.com/HorizenOfficial/staker";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="hl-label hl-section-label" style={{ display: "block", margin: "34px 0 14px" }}>
      {children}
    </h2>
  );
}

// A single trust/security point.
function Point({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        borderLeft: "3px solid var(--hl-sunrise)",
        background: "var(--hl-grey-light)",
        borderRadius: "0 var(--hl-radius-sm) var(--hl-radius-sm) 0",
        padding: "18px 20px",
      }}
    >
      <h3 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 8px" }}>{title}</h3>
      <p style={{ color: "var(--hl-grey-text)", fontSize: 13.5, margin: 0, lineHeight: 1.55 }}>
        {children}
      </p>
    </div>
  );
}

// A numbered step in the rewards-distribution explainer.
function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: "var(--hl-space-5)", alignItems: "flex-start" }}>
      <span
        aria-hidden
        style={{
          flex: "none",
          width: 26,
          height: 26,
          marginTop: 2,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: 6,
          background: "var(--hl-sunrise)",
          color: "var(--hl-deep-blue)",
          fontWeight: 700,
          fontSize: 12.5,
        }}
      >
        {n}
      </span>
      <div>
        <h3 style={{ fontSize: 16.5, fontWeight: 600, margin: "0 0 6px" }}>{title}</h3>
        <p style={{ color: "var(--hl-grey-text)", fontSize: 14, margin: 0, lineHeight: 1.55 }}>
          {children}
        </p>
      </div>
    </div>
  );
}

// A labelled contract/network reference row with an explorer link.
function RefRow({
  label,
  value,
  href,
}: {
  label: string;
  value: string;
  href: string | null;
}) {
  return (
    <div
      className="hl-ref-row"
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: "var(--hl-space-5)",
        padding: "var(--hl-space-4) 0",
        borderTop: "1px solid var(--hl-grey)",
      }}
    >
      <span className="hl-label">{label}</span>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="hl-address hl-ref-value hl-contract-link"
          style={{ whiteSpace: "nowrap" }}
        >
          {value} ↗
        </a>
      ) : (
        <span className="hl-address hl-ref-value hl-contract-link" style={{ whiteSpace: "nowrap" }}>
          {value}
        </span>
      )}
    </div>
  );
}

export function HowItWorks() {
  const symbol = useTokenSymbol();
  return (
    <div className="hl-wrap">
      <div className="hl-page-head">
        <h1>
          How it <em>works</em>.
        </h1>
        <p className="hl-page-sub">Security and transparency by design.</p>
      </div>

      <div className="hl-card">
        <p className="hl-intro">
          {symbol} staking is the official staking program for the Horizen chain.{" "}
          <b style={{ color: "var(--hl-navy-hover)" }}>Fully on-chain and non-custodial.</b> Your {symbol} is locked
          only inside the public staking contract — no intermediary ever takes custody — and every
          balance, reward and transaction is verifiable on the block explorer.
        </p>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "var(--hl-space-8)",
            marginBottom: "var(--hl-space-10)",
          }}
        >
          <Point title="Audited contracts">
            Built on Horizen&apos;s audited{" "}
            <a
              href={CONTRACTS_SOURCE_URL}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "var(--hl-sunrise-light)", textDecoration: "underline" }}
            >
              staker contracts
            </a>
            , open-source and independently reviewed.
          </Point>
          <Point title="Non-custodial">
            Funds stay in your control at all times. You interact with the contract
            directly from your own wallet — there is no backend that can move your {symbol}.
          </Point>
          <Point title="No lock-up">
            Stake, claim and withdraw whenever you want. Your principal is never
            frozen and rewards accrue continuously, block by block.
          </Point>
        </div>

        <SectionLabel>How rewards are accrued</SectionLabel>
        <p className="hl-intro">
          Rewards are funded from multiple independent sources and streamed to stakers
          automatically — there is no manual allocation and no discretionary payout.
        </p>
        <div
          style={{
            display: "grid",
            gap: "var(--hl-space-6)",
            marginBottom: "var(--hl-space-10)",
          }}
        >
          <Step n={1} title="Varied rewards sources fund the contract">
            Varied rewards sources periodically top up the staking contract by sending {symbol}{" "}
            through the on-chain reward-notification method (
            <code
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 12.5,
                color: "var(--hl-navy-hover)",
                background: "var(--hl-grey-light)",
                borderRadius: 5,
                padding: "2px 7px",
              }}
            >
              notifyRewardAmount
            </code>
            ). Every top-up is a public transaction, verifiable on the block explorer.
          </Step>
          <Step n={2} title="You accrue continuously, pro-rata">
            While the window is active, rewards accrue every block in proportion to your share of
            the total staked {symbol}. Nothing needs to be done for them to grow — your balance
            updates automatically.
          </Step>
          <Step n={3} title="Claim anytime — nothing is lost">
            Accrued rewards are held for you on-chain and keep accumulating until you
            claim. There is no lock-up and no deadline: claim whenever you like.
          </Step>
        </div>

        <SectionLabel>Official contracts and network</SectionLabel>
        <p style={{ margin: "0 0 var(--hl-space-6)", color: "var(--hl-grey-text)", lineHeight: 1.6 }}>
          Protect your funds! <b>Only trust the original Horizen contracts
          listed here</b>.
        </p>
        <div>
          <RefRow
            label="Staking contract"
            value={(CONFIG.contractStaker)}
            href={addressUrl(CONFIG.contractStaker)}
          />
          <RefRow
            label={`${symbol} token`}
            value={(CONFIG.contractToken)}
            href={tokenUrl(CONFIG.contractToken)}
          />
          <RefRow
            label="Network"
            value={`Chain ID ${CONFIG.chainId}`}
            href={CONFIG.explorerUrl ? CONFIG.explorerUrl.replace(/\/+$/, "") : null}
          />
        </div>
      </div>
    </div>
  );
}
