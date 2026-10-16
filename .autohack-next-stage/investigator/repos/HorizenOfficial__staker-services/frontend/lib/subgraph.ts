import { CONFIG } from "./config";

// Minimal GraphQL POST helper against the ZenStaker subgraph.
async function query<T>(gql: string, variables: Record<string, unknown>): Promise<T> {
  const res = await fetch(CONFIG.subgraph, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: gql, variables }),
  });
  if (!res.ok) throw new Error(`Subgraph HTTP ${res.status}`);
  const json = await res.json();
  if (json.errors) throw new Error(json.errors[0]?.message ?? "Subgraph query error");
  return json.data as T;
}

const USER_DEPOSITS = /* GraphQL */ `
  query UserDeposits($owner: Bytes!) {
    deposits(first: 1000, where: { owner: $owner }) {
      id
      stakedAmount
      earningPower
    }
  }
`;

export interface SubgraphDeposit {
  id: string;
  stakedAmount: string;
  earningPower: string;
}

// All deposit IDs ever opened by an owner, including fully-withdrawn ones —
// a withdrawal zeroes stakedAmount but not unclaimedReward, so a
// stakedAmount_gt filter here would permanently hide deposits that still
// have rewards to claim. Callers filter for display using live chain reads
// (balance / unclaimedRewards), not this raw list. Owner must be lowercased.
export async function fetchUserDeposits(owner: string): Promise<SubgraphDeposit[]> {
  const data = await query<{ deposits: SubgraphDeposit[] }>(USER_DEPOSITS, {
    owner: owner.toLowerCase(),
  });
  return data.deposits;
}

// Short-lived cache + in-flight coalescing for deposit IDs. The dashboard mounts
// two hooks (useUserSummary + useDeposits) that each need the same IDs on every
// poll cycle; without this they'd fire two identical subgraph queries per tick.
// In-flight coalescing merges the two simultaneous calls into one request; the
// TTL absorbs minor timer skew between them. Kept well below the poll interval
// (and below the post-action reload delay) so data stays fresh.
const ID_CACHE_TTL_MS = 4_000;
const depositIdsCache = new Map<string, { ts: number; ids: bigint[] }>();
const depositIdsInflight = new Map<string, Promise<bigint[]>>();

export async function fetchUserDepositIds(owner: string): Promise<bigint[]> {
  const key = owner.toLowerCase();

  const cached = depositIdsCache.get(key);
  if (cached && Date.now() - cached.ts < ID_CACHE_TTL_MS) return cached.ids;

  const inflight = depositIdsInflight.get(key);
  if (inflight) return inflight;

  const request = fetchUserDeposits(owner)
    .then((deposits) => {
      const ids = deposits.map((d) => BigInt(d.id));
      depositIdsCache.set(key, { ts: Date.now(), ids });
      return ids;
    })
    .finally(() => {
      depositIdsInflight.delete(key);
    });

  depositIdsInflight.set(key, request);
  return request;
}

// ---- Activity / history -----------------------------------------------------

export type ActivityType = "stake" | "withdraw" | "claim";

export interface ActivityItem {
  type: ActivityType;
  amount: bigint;
  depositId: string;
  timestamp: number; // unix seconds
  txHash: string;
  orderKey: bigint; // cursor: (blockNumber << 32) | logIndex, strictly increasing
}

interface RawActivity {
  kind: string;
  amount: string;
  depositId: string;
  orderKey: string;
  blockTimestamp: string;
  transactionHash: string;
}

// orderKey is (blockNumber << 32) | logIndex, far below 2^128. This sentinel
// sits above any real cursor, so the first page (cursor=null) returns the newest
// rows — graph-node rejects a null comparison filter, so we always send a value.
const MAX_CURSOR = (1n << 128n) - 1n;

// Single, globally-ordered activity feed. `orderKey_lt: $cursor` pages strictly
// older rows. One entity means the merged timeline has no per-type holes.
const USER_ACTIVITY = /* GraphQL */ `
  query Activity($owner: Bytes!, $first: Int!, $cursor: BigInt) {
    activities(
      where: { account: $owner, orderKey_lt: $cursor }
      orderBy: orderKey
      orderDirection: desc
      first: $first
    ) {
      kind
      amount
      depositId
      orderKey
      blockTimestamp
      transactionHash
    }
  }
`;

// One page of an owner's activity, newest first. `cursor` is the orderKey of the
// oldest item already shown; pass null for the first (most recent) page.
export async function fetchUserActivity(
  owner: string,
  first: number,
  cursor: bigint | null
): Promise<ActivityItem[]> {
  const data = await query<{ activities: RawActivity[] }>(USER_ACTIVITY, {
    owner: owner.toLowerCase(),
    first,
    cursor: (cursor === null ? MAX_CURSOR : cursor).toString(),
  });

  return data.activities.map((a) => ({
    type: a.kind as ActivityType,
    amount: BigInt(a.amount),
    depositId: a.depositId,
    timestamp: Number(a.blockTimestamp),
    txHash: a.transactionHash,
    orderKey: BigInt(a.orderKey),
  }));
}

export interface SubgraphMeta {
  block: number; // latest indexed block
  hasIndexingErrors: boolean;
}

export async function fetchSubgraphMeta(): Promise<SubgraphMeta> {
  const data = await query<{
    _meta: { block: { number: number }; hasIndexingErrors: boolean } | null;
  }>(`{ _meta { block { number } hasIndexingErrors } }`, {});
  if (!data._meta) throw new Error("Subgraph returned no _meta");
  return { block: data._meta.block.number, hasIndexingErrors: data._meta.hasIndexingErrors };
}
