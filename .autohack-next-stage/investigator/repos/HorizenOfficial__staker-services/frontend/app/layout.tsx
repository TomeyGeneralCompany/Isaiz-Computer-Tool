import type { Metadata } from "next";
import { Funnel_Display, Montserrat } from "next/font/google";
import { WalletProvider } from "@/lib/wallet";
import { LearnedDepositsProvider } from "@/lib/learnedDeposits";
import { Header } from "@/components/Header";
import { TestnetBanner } from "@/components/TestnetBanner";
import { SubgraphHealthBanner } from "@/components/SubgraphHealthBanner";
import { Footer } from "@/components/Footer";
import "./globals.css";

// Self-hosted at build time (no runtime fetch to fonts.googleapis.com), so
// headings render in Funnel Display / Montserrat even when the browser has
// no network access to Google's font CDN.
const funnelDisplay = Funnel_Display({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  variable: "--font-display",
});
const montserrat = Montserrat({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
});

export const metadata: Metadata = {
  title: "Horizen — Stake ZEN. Earn on Horizen.",
  description: "Stake ZEN to earn ZEN rewards on the Horizen staking program.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={`${funnelDisplay.variable} ${montserrat.variable}`}>
        <WalletProvider>
          <LearnedDepositsProvider>
            <Header />
            <TestnetBanner />
            <SubgraphHealthBanner />
            <main
              id="main-content"
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
              }}
            >
              {children}
              <Footer />
            </main>
          </LearnedDepositsProvider>
        </WalletProvider>
      </body>
    </html>
  );
}
