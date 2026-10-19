import { createLogger } from "@bounty/core";

const log = createLogger("huntr-client");

export interface HuntrProgram {
  id: string;
  handle: string;
  name: string;
  url: string;
  repoUrl: string;
  rewardMaxCents: number | null;
  rewardMinCents: number | null;
}

/**
 * The former repository bounty feed at /bounties is unavailable. Keep the
 * adapter callable for existing configurations, but do not reinterpret unrelated
 * page links as program scope or invent reward amounts. A replacement requires
 * a documented feed with explicit repository eligibility and reward metadata.
 */
export async function fetchHuntrPrograms(): Promise<HuntrProgram[]> {
  log.warn("Huntr repository discovery unavailable: retired /bounties feed; no programs imported");
  return [];
}
