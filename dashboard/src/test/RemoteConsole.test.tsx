import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import RemoteConsole from "../components/RemoteConsole";
import { api, ApiError } from "../lib/api";
import { ToastProvider } from "../components/toast";

vi.mock("../lib/api", async (original) => ({
  ...await original<typeof import("../lib/api")>(),
  api: { get: vi.fn(), post: vi.fn() },
}));

const session = { id: "session_test", agent_id: "agt_test", status: "active", last_active_at: null };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.get).mockResolvedValue({ session, commands: [] });
  vi.mocked(api.post).mockResolvedValue(session);
});

async function connect() {
  render(<ToastProvider><RemoteConsole agentId="agt_test" agentLabel="test-host" /></ToastProvider>);
  fireEvent.click(screen.getByRole("button", { name: "اتصال به عامل و ساخت نشست" }));
  await waitFor(() => expect(api.get).toHaveBeenCalled());
  return screen.getByRole("button", { name: "بستن نشست" });
}

it("keeps a live console session and reports a failed termination, allowing retry", async () => {
  const close = await connect();
  vi.mocked(api.post).mockRejectedValueOnce(new ApiError(503, "عامل در دسترس نیست"));
  fireEvent.click(close);
  await waitFor(() => expect(screen.getAllByText("عامل در دسترس نیست")).toHaveLength(2));
  expect(screen.getByRole("textbox")).toBeEnabled();
  expect(screen.queryByText("نشست کنسول بسته شد.")).not.toBeInTheDocument();
  fireEvent.click(close);
  await waitFor(() => expect(screen.getByRole("button", { name: "اتصال به عامل و ساخت نشست" })).toBeEnabled());
  expect(document.querySelector(".terminal-out")?.textContent).not.toContain("عامل در دسترس نیست");
  expect(api.post).toHaveBeenLastCalledWith("/api/admin/v1/console/sessions/session_test/terminate", {});
});

it.each([404, 410])("clears an already missing or expired session after termination returns %s", async (status) => {
  const close = await connect();
  vi.mocked(api.post).mockRejectedValueOnce(new ApiError(status, "نشست وجود ندارد"));
  fireEvent.click(close);
  await waitFor(() => expect(screen.getByRole("button", { name: "اتصال به عامل و ساخت نشست" })).toBeEnabled());
  expect(screen.getByRole("textbox")).toBeDisabled();
  expect(screen.getByText("نشست کنسول بسته شد.")).toBeInTheDocument();
});
