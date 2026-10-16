"use client";

import { useCallback, useRef, useState } from "react";
import { fetchUserActivity, type ActivityItem } from "./subgraph";
import { usePolling } from "./usePolling";

const POLL_MS = 20_000;
const PAGE = 25;

export interface ActivityState {
  items: ActivityItem[];
  loading: boolean;
  error: string | null;
  canLoadMore: boolean;
  loadMore: () => void;
  reload: () => Promise<void>;
}

// Cursor-paginated history over the unified `Activity` entity. `loadMore` pages
// strictly older rows via `orderKey_lt`; polling refetches only the newest page
// and merges new rows in — neither refetches the whole loaded range. Items are
// keyed by `orderKey` (globally unique & ordered), so merges dedupe cleanly and
// the timeline has no holes.
export function useActivity(address: string | null): ActivityState {
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [canLoadMore, setCanLoadMore] = useState(false);

  const byKey = useRef<Map<string, ActivityItem>>(new Map());
  const lastAddress = useRef<string | null>(null);

  const apply = useCallback(() => {
    const sorted = [...byKey.current.values()].sort((a, b) =>
      a.orderKey < b.orderKey ? 1 : a.orderKey > b.orderKey ? -1 : 0
    );
    setItems(sorted);
  }, []);

  // Most-recent page. Used for the initial load and each poll: on the first
  // load it also decides `canLoadMore`; on later polls it only merges newer rows
  // and leaves the deeper-history flag untouched.
  const loadLatest = useCallback(async () => {
    if (!address) {
      byKey.current = new Map();
      lastAddress.current = null;
      setItems([]);
      setCanLoadMore(false);
      return;
    }
    if (lastAddress.current !== address) {
      lastAddress.current = address;
      byKey.current = new Map();
      setItems([]);
      setCanLoadMore(false);
    }
    setLoading(true);
    try {
      const wasEmpty = byKey.current.size === 0;
      const page = await fetchUserActivity(address, PAGE, null);
      page.forEach((i) => byKey.current.set(i.orderKey.toString(), i));
      apply();
      if (wasEmpty) setCanLoadMore(page.length === PAGE);
      setError(null);
    } catch {
      setError("Unable to load history — subgraph unavailable.");
    } finally {
      setLoading(false);
    }
  }, [address, apply]);

  const loadMore = useCallback(async () => {
    if (!address || items.length === 0) return;
    const oldest = items[items.length - 1].orderKey;
    setLoading(true);
    try {
      const page = await fetchUserActivity(address, PAGE, oldest);
      page.forEach((i) => byKey.current.set(i.orderKey.toString(), i));
      apply();
      setCanLoadMore(page.length === PAGE);
      setError(null);
    } catch {
      setError("Unable to load history — subgraph unavailable.");
    } finally {
      setLoading(false);
    }
  }, [address, items, apply]);

  usePolling(loadLatest, POLL_MS, !!address);

  return { items, loading, error, canLoadMore, loadMore, reload: loadLatest };
}
