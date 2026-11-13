import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import InvestigationsPage from "../pages/Investigations";
import { api, ApiError } from "../lib/api";

vi.mock("../lib/api", async (original) => ({
  ...await original<typeof import("../lib/api")>(),
  api: { get: vi.fn(), post: vi.fn() },
}));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.get).mockResolvedValue({ items: [] });
  vi.mocked(api.post).mockResolvedValue({ id: 1 });
});

async function openPanel(deep = false) {
  const view = render(<InvestigationsPage />);
  fireEvent.click(screen.getByRole("button", { name: "+ بررسی جدید" }));
  fireEvent.change(screen.getByLabelText("هدف (IP میزبان)"), { target: { value: "192.0.2.10" } });
  if (deep) fireEvent.click(screen.getByRole("radio", { name: /Deep/ }));
  await act(async () => {});
  return view;
}

it("allows another explicit quick investigation after success without submitting duplicates", async () => {
  await openPanel();
  fireEvent.click(screen.getByRole("button", { name: "▶ Start Investigation" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "▶ Start Investigation" })).toBeEnabled());
  expect(api.post).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "▶ Start Investigation" }));
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByRole("button", { name: "▶ Start Investigation" })).toBeEnabled());
});

it.each(["completed", "failed", "cancelled", "interrupted"])("stops tracking a terminal %s background job", async (status) => {
  vi.mocked(api.post).mockResolvedValue({ job_id: "selected-job" });
  vi.mocked(api.get).mockImplementation(async (path) => path.startsWith("/api/jobs/")
    ? { status, error: status === "completed" ? null : "job stopped" } : { items: [] });
  await openPanel(true);
  fireEvent.click(screen.getByRole("button", { name: "▶ Start Investigation" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "▶ Start Investigation" })).toBeEnabled());
  expect(api.get).toHaveBeenCalledWith("/api/jobs/selected-job", expect.anything());
  expect(api.post).toHaveBeenCalledTimes(1);
});

it("does not create a new polling timer when an in-flight job read completes after unmount", async () => {
  let finish!: (value: unknown) => void;
  vi.mocked(api.post).mockResolvedValue({ job_id: "selected-job" });
  vi.mocked(api.get).mockImplementation(async (path) => path.startsWith("/api/jobs/")
    ? new Promise((resolve) => { finish = resolve; }) : { items: [] });
  const view = await openPanel(true);
  fireEvent.click(screen.getByRole("button", { name: "▶ Start Investigation" }));
  await waitFor(() => expect(finish).toBeDefined());
  view.unmount();
  vi.useFakeTimers();
  try {
    await act(async () => { finish({ status: "running", error: null }); });
    expect(vi.getTimerCount()).toBe(0);
  } finally { vi.useRealTimers(); }
});

it("reports suggestion lookup errors and permits a retry without starting an investigation", async () => {
  vi.mocked(api.get).mockImplementation(async (path) => {
    if (path.startsWith("/api/hosts")) throw new ApiError(503, "فهرست میزبان در دسترس نیست");
    return { items: [] };
  });
  await openPanel();
  await screen.findByText(/فهرست میزبان در دسترس نیست/);
  vi.mocked(api.get).mockResolvedValue({ items: [] });
  fireEvent.click(screen.getByRole("button", { name: "تلاش دوباره برای فهرست هدف‌ها" }));
  await waitFor(() => expect(screen.queryByText(/فهرست میزبان در دسترس نیست/)).not.toBeInTheDocument());
  expect(api.post).not.toHaveBeenCalled();
});
