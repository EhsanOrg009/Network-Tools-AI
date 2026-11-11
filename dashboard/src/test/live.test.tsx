import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useLiveFeed } from "../lib/live";

afterEach(() => vi.useRealTimers());

describe("connection polling", () => {
  it("keeps one timer when the caller supplies an inline function", async () => {
    vi.useFakeTimers();
    const check = vi.fn().mockImplementation(() => new Promise<boolean>(() => {})).mockResolvedValueOnce(true);
    const { result, rerender, unmount } = renderHook(() => useLiveFeed(20000, () => check()));
    await act(async () => {});
    rerender();
    await act(async () => {});
    expect(check).toHaveBeenCalledTimes(1);
    const lastSync = result.current.lastSync;
    check.mockResolvedValue(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
    expect(check).toHaveBeenCalledTimes(2);
    expect(result.current.ok).toBe(false);
    expect(result.current.lastSync).toBe(lastSync);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("never overlaps a slow health request", async () => {
    vi.useFakeTimers();
    let finish!: (ok: boolean) => void;
    const check = vi.fn(() => new Promise<boolean>((resolve) => { finish = resolve; }));
    const { unmount } = renderHook(() => useLiveFeed(1000, check));
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(check).toHaveBeenCalledTimes(1);
    unmount();
    await act(async () => { finish(true); });
    expect(vi.getTimerCount()).toBe(0);
  });
});
