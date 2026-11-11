import { useEffect } from "react";

/** A settled request precedes the next poll; cleanup cancels stale results. */
export function usePolling(load: (signal: AbortSignal) => Promise<void>, interval: number, live: boolean, refreshKey: number) {
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      await load(controller.signal);
      if (!controller.signal.aborted && live) timer = setTimeout(() => { void refresh(); }, interval);
    };
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [load, interval, live, refreshKey]);
}
