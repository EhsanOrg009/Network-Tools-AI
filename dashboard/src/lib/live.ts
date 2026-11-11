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
  const check = useRef(asyncCheck);
  const inFlight = useRef<Promise<boolean> | null>(null);
  check.current = asyncCheck;

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const run = async () => {
      if (cancelled) return;
      window.clearTimeout(timer);
      // Reuse a pending request even across effect cleanup (StrictMode,
      // force refresh). Schedule the next poll only after it settles.
      const pending = inFlight.current ?? Promise.resolve().then(() => check.current()).catch(() => false);
      inFlight.current = pending;
      const ok = await pending;
      if (inFlight.current === pending) inFlight.current = null;
      if (cancelled) return;
      setFeed((f) => ({ ok, lastSync: ok ? Date.now() : f.lastSync }));
      timer = window.setTimeout(() => { void run(); }, pollMs);
    };
    void run();
    const onVisible = () => {
      if (document.visibilityState === "visible" && !inFlight.current) void run();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [pollMs, tick]);

  const forceRefresh = useCallback(() => setTick((t) => t + 1), []);
  return { ...feed, forceRefresh };
}
