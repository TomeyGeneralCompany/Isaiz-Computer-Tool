import type { Metadata } from "next";
import "./globals.css";
import { TRPCProvider } from "@/components/trpc-provider";
import { Nav } from "@/components/nav";

export const metadata: Metadata = {
  title: "Tomey Gun | Tomey General Company",
  icons: { icon: "/constanzo.png" },
  description: "Tomey Gun — the local bounty research dashboard from Tomey General Company.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <TRPCProvider>
          <Nav />
          <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
        </TRPCProvider>
      </body>
    </html>
  );
}
