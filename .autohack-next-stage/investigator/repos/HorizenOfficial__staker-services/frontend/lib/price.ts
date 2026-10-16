"use client";

import { useEffect, useState } from "react";
import { CONFIG } from "./config";

// Spot USD price for the staked token, from CoinGecko's public simple-price
// endpoint (no API key required). Cached process-wide and refreshed on an
// interval — this is a display estimate ("Staked value"), not something any
// transaction depends on.
const TTL_MS = 60_000;

let cachedPrice: number | null = null;
let cachedAt = 0;
let inflight: Promise<number | null> | null = null;

async function fetchPrice(): Promise<number | null> {
  if (!CONFIG.coingeckoId) return null;
  if (cachedPrice !== null && Date.now() - cachedAt < TTL_MS) return cachedPrice;
  if (inflight) return inflight;

  inflight = (async () => {
    try {
      const res = await fetch(
        `https://api.coingecko.com/api/v3/simple/price?ids=${CONFIG.coingeckoId}&vs_currencies=usd`
      );
      if (!res.ok) throw new Error(`CoinGecko HTTP ${res.status}`);
      const json = await res.json();
      const price = json?.[CONFIG.coingeckoId]?.usd;
      if (typeof price !== "number") throw new Error("Unexpected CoinGecko response shape");
      cachedPrice = price;
      cachedAt = Date.now();
      return price;
    } catch {
      return null;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

// Live USD price, or null while loading / if disabled / on fetch failure.
export function useTokenPriceUsd(): number | null {
  const [price, setPrice] = useState<number | null>(cachedPrice);

  useEffect(() => {
    let active = true;
    const load = () => {
      fetchPrice().then((p) => {
        if (active) setPrice(p);
      });
    };
    load();
    const id = setInterval(load, TTL_MS);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  return price;
}
