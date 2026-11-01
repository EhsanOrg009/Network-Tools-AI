/**
 * Live-connection hook: periodic light-weight health call to the core.
 * Tracks ok / lost; on loss keeps stale data but surfaces the disconnect.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface Feed {
  ok: boolean;
  lastSync: number | null; // epoch ms of last successful sync
}

export function useLiveFeed(pollMs = 20000, asyncCheck: () => Promise<boolean>) {
  const [feed, setFeed] = useState<Feed>({ ok: true, lastSync: null });
  const [tick, setTick] = useState(0);
  const timer = useRef<number | null>(null);
  const alive = useRef(true);

  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const refresh = useCallback(async () => {
    try {
      const ok = await asyncCheck();
      setFeed({ ok, lastSync: ok ? Date.now() : undefined as unknown as number });
      if (!ok) throw new Error("unavailable");
      setFeed({ ok: true, lastSync: Date.now() });
    } catch {
      setFeed((f) => ({ ok: false, lastSync: f.lastSync }));
    }
  }, [asyncCheck]);

  useEffect(() => {
    let cancelled = false;
    void refresh();
    const run = () => {
      if (!alive.current) return;
      void refresh();
      timer.current = window.setTimeout(run, pollMs);
    };
    timer.current = window.setTimeout(run, pollMs);
    const onVisible = () => {
      if (document.visibilityState === "visible" && !cancelled) void refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      if (timer.current) window.clearTimeout(timer.current);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refresh, pollMs, tick]);

  const forceRefresh = useCallback(() => setTick((t) => t + 1), []);
  return { ...feed, forceRefresh };
}
