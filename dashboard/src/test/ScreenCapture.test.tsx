import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ScreenCapture from "../components/ScreenCapture";
import { api } from "../lib/api";

vi.mock("../lib/api", () => ({ api: { get: vi.fn(), post: vi.fn() } }));
afterEach(() => vi.unstubAllGlobals());

it("does not start screenshot polling after the requesting component unmounts", async () => {
  vi.clearAllMocks();
  let finish!: (result: unknown) => void;
  vi.mocked(api.post).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const { unmount } = render(<ScreenCapture agentId="agt_test" />);
  fireEvent.click(screen.getByRole("button", { name: "دریافت تصویر صفحه" }));
  unmount();
  await act(async () => { finish({ task_id: "task_test" }); });
  expect(api.get).not.toHaveBeenCalled();
});

it("releases a displayed image URL on unmount", async () => {
  vi.mocked(api.post).mockResolvedValue({ task_id: "task_test" });
  vi.mocked(api.get).mockResolvedValue({ status: "succeeded" });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, blob: async () => new Blob(["test-image"]) }));
  const create = vi.fn().mockReturnValue("blob:test-image");
  const revoke = vi.fn();
  vi.stubGlobal("URL", Object.assign(class extends URL {}, { createObjectURL: create, revokeObjectURL: revoke }));
  const { unmount } = render(<ScreenCapture agentId="agt_test" />);
  fireEvent.click(screen.getByRole("button", { name: "دریافت تصویر صفحه" }));
  await waitFor(() => expect(screen.getByRole("img")).toHaveAttribute("src", "blob:test-image"));
  unmount();
  expect(revoke).toHaveBeenCalledWith("blob:test-image");
});
