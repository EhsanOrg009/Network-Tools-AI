import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import AnalysisHistory from "../components/AnalysisHistory";
import { api, ApiError } from "../lib/api";

vi.mock("../lib/api", async (original) => ({
  ...await original<typeof import("../lib/api")>(),
  api: { get: vi.fn(), post: vi.fn() },
}));

const archive = { alert_id: 34, job_id: "previous", status: "FAILED", summary: null,
  error: "LLMTimeout", evidence: [], recommendation: null, model: "test", analyzed_at: null };
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.get).mockResolvedValue({ items: [archive], total: 21 }); });

it("reads bounded pages only after opening history and never submits analysis", async () => {
  render(<AnalysisHistory alertId={34} jobId="current" />);
  expect(api.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "تاریخچهٔ تلاش‌های قبلی" }));
  await screen.findByText("LLMTimeout");
  expect(api.get).toHaveBeenCalledWith("/api/admin/v1/ai-analyses/34/history?limit=20&offset=0", expect.anything());
  fireEvent.click(screen.getByRole("button", { name: "تاریخچهٔ قدیمی‌تر" }));
  await waitFor(() => expect(api.get).toHaveBeenLastCalledWith("/api/admin/v1/ai-analyses/34/history?limit=20&offset=20", expect.anything()));
  await screen.findByText("LLMTimeout");
  expect(api.post).not.toHaveBeenCalled();
});

it("shows a history read error and retries without producing a job", async () => {
  vi.mocked(api.get).mockRejectedValueOnce(new ApiError(503, "تاریخچه در دسترس نیست"));
  render(<AnalysisHistory alertId={34} />);
  fireEvent.click(screen.getByRole("button", { name: "تاریخچهٔ تلاش‌های قبلی" }));
  await screen.findByText("تاریخچه در دسترس نیست");
  vi.mocked(api.get).mockResolvedValue({ items: [], total: 0 });
  fireEvent.click(screen.getByRole("button", { name: "تلاش دوباره" }));
  await screen.findByText("تلاش قبلی ثبت نشده");
  expect(api.post).not.toHaveBeenCalled();
});

it("rejects a history response attributed to a different event", async () => {
  vi.mocked(api.get).mockResolvedValue({ items: [{ ...archive, alert_id: 35 }], total: 1 });
  render(<AnalysisHistory alertId={34} />);
  fireEvent.click(screen.getByRole("button", { name: "تاریخچهٔ تلاش‌های قبلی" }));
  await screen.findByText("پاسخ تاریخچهٔ این هشدار معتبر نیست.");
  expect(screen.queryByText("LLMTimeout")).not.toBeInTheDocument();
});

it("cancels an old history read when the current attempt changes", async () => {
  let finish!: (value: unknown) => void;
  vi.mocked(api.get).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
  const view = render(<AnalysisHistory alertId={34} jobId="one" />);
  fireEvent.click(screen.getByRole("button", { name: "تاریخچهٔ تلاش‌های قبلی" }));
  view.rerender(<AnalysisHistory alertId={34} jobId="two" />);
  await screen.findByText("LLMTimeout");
  await act(async () => { finish({ items: [], total: 0 }); });
  expect(screen.getByText("LLMTimeout")).toBeInTheDocument();
});
