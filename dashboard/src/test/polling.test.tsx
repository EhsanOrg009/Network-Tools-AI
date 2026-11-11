import { act, renderHook } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { usePolling } from "../lib/polling";

afterEach(() => vi.useRealTimers());

it("waits for a slow request before scheduling another poll and aborts on unmount", async () => {
  vi.useFakeTimers();
  const finishes: (() => void)[] = [];
  const load = vi.fn((_signal: AbortSignal) => new Promise<void>((resolve) => finishes.push(resolve)));
  const { unmount } = renderHook(() => usePolling(load, 1000, true, 0));
  await act(async () => { vi.advanceTimersByTime(10000); });
  expect(load).toHaveBeenCalledTimes(1);
  await act(async () => { finishes[0](); });
  await act(async () => { vi.advanceTimersByTime(1000); });
  expect(load).toHaveBeenCalledTimes(2);
  unmount();
  expect(load.mock.calls[1][0].aborted).toBe(true);
  await act(async () => { finishes[1](); vi.advanceTimersByTime(10000); });
  expect(load).toHaveBeenCalledTimes(2);
});

it("refreshes once with live polling disabled", async () => {
  vi.useFakeTimers();
  const load = vi.fn(async () => {});
  renderHook(() => usePolling(load, 1000, false, 0));
  await act(async () => { vi.advanceTimersByTime(10000); });
  expect(load).toHaveBeenCalledTimes(1);
});
