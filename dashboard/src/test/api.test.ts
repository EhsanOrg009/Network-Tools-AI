import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError, getToken, setToken } from "../lib/api";

beforeEach(() => { localStorage.clear(); });
afterEach(() => vi.unstubAllGlobals());

it("clears a rejected stored token and notifies the application", async () => {
  setToken("expired-token");
  const changed = vi.fn();
  window.addEventListener("netagent-auth", changed);
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"detail":"توکن نامعتبر"}', { status: 401 })));
  await expect(api.get("/api/dashboard/v1/healthz")).rejects.toThrow("توکن نامعتبر");
  expect(getToken()).toBe("");
  expect(changed).toHaveBeenCalledTimes(1);
  window.removeEventListener("netagent-auth", changed);
});

it("validates a login candidate without storing it or clearing another session", async () => {
  setToken("existing-session");
  const fetcher = vi.fn().mockResolvedValue(new Response('{"detail":"invalid"}', { status: 401 }));
  vi.stubGlobal("fetch", fetcher);
  await expect(api.get("/api/dashboard/v1/healthz", { token: "candidate" })).rejects.toBeInstanceOf(ApiError);
  expect(getToken()).toBe("existing-session");
  expect(fetcher.mock.calls[0][1].headers.Authorization).toBe("Bearer candidate");
});

it("shows validation messages and rejects non-JSON successful responses", async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(new Response('{"detail":[{"msg":"Invalid IP"}]}', { status: 422 }))
    .mockResolvedValueOnce(new Response("<html>proxy error</html>"));
  vi.stubGlobal("fetch", fetcher);
  await expect(api.post("/api/test", {})).rejects.toThrow("Invalid IP");
  await expect(api.get("/api/test")).rejects.toThrow("JSON");
});
