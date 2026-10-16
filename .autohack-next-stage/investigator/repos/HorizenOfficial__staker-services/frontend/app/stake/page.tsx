"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// The Stake tab was removed — staking is handled via the dashboard dialog.
// Client-side redirect (static export has no server to issue a 3xx).
export default function StakePage() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/");
  }, [router]);
  return null;
}
