import { CONFIG } from "@/lib/config";

export function Footer() {
  return (
    <footer className="hl-footer">
      <span>ZEN staking runs on Horizen, an L3 on Base. Reward rates vary and are not guaranteed.</span>
      <div className="hl-footer-links">
        {CONFIG.explorerUrl ? (
          <a href={CONFIG.explorerUrl.replace(/\/+$/, "")} target="_blank" rel="noopener noreferrer">
            Block explorer ↗
          </a>
        ) : null}
        {CONFIG.termsUrl ? (
          <a href={CONFIG.termsUrl} target="_blank" rel="noopener noreferrer">
            Terms & Conditions ↗
          </a>
        ) : null}
      </div>
    </footer>
  );
}
