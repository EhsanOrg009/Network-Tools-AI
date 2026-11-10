import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { Mocked } from "vitest";
import SecurityPage from "../pages/Security";
import * as apiModule from "../lib/api";
import { MemoryRouter } from "react-router-dom";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } };
});

const mockedApi = apiModule.api as unknown as Mocked<typeof apiModule.api>;

const ALERT = {
  id: 34, ts: "2026-11-01T10:00:00+00:00", severity: 2,
  signature: "SURICATA TLS Obsolete Version", signature_id: 22000300,
  src_ip: "192.168.1.10", dest_ip: "142.250.185.68", src_port: 52311,
  dest_port: 443, proto: "TCP", app_proto: "tls", action: "allowed",
};

const STATUS = {
  auto_enabled: false, counts: { PENDING: 0, PROCESSING: 0, COMPLETED: 0, FAILED: 0 },
  last_processed_at: null, last_error: null, model: "gemma-4-e4b:latest",
  connection: { ok: true, detail: "ready" }, worker_enabled: true,
};

function mockBackend({ analyses }: { analyses: unknown[] }) {
  mockedApi.get.mockImplementation(async (path: string) => {
    if (path.startsWith("/api/alerts")) return { items: [ALERT], total: 1 };
    if (path === "/api/admin/v1/security-ai") return STATUS;
    if (path.startsWith("/api/admin/v1/ai-analyses")) return { items: analyses };
    throw new apiModule.ApiError(500, "unexpected " + path);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockedApi.post.mockResolvedValue({});
  mockedApi.put.mockResolvedValue({});
});

function renderPage() {
  return render(<MemoryRouter><SecurityPage /></MemoryRouter>);
}

describe("SecurityPage AI analysis", () => {
  it("renders the completed analysis summary in the AI column", async () => {
    mockBackend({
      analyses: [{
        alert_id: 34, status: "COMPLETED", summary: "تطابق امضای نسخه قدیمی TLS؛ رفتار رایج.",
        importance: "low", evidence: ["action=allowed"], anomaly_likelihood: "low",
        confidence: "medium", recommendation: "بررسی دوره‌ای کافی است.", model: "m",
        prompt_version: "alert-analysis-v1", error: null, attempts: 1, analyzed_at: null,
      }],
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("تطابق امضای نسخه قدیمی TLS؛ رفتار رایج.")).toBeInTheDocument(),
    );
  });

  it("shows pending/failed states without crashing", async () => {
    mockBackend({ analyses: [{ alert_id: 34, status: "PENDING" }] });
    renderPage();
    await waitFor(() => expect(screen.getByText("در صف")).toBeInTheDocument());
  });

  it("opens the detail modal with the full analysis and re-analyze calls the admin API", async () => {
    mockBackend({
      analyses: [{
        alert_id: 34, status: "COMPLETED", summary: "خلاصه تحلیل", importance: "low",
        evidence: ["action=allowed"], anomaly_likelihood: "low", confidence: "medium",
        recommendation: "اقدامی لازم نیست.", model: "gemma", prompt_version: "v1",
        error: null, attempts: 1, analyzed_at: null,
      }],
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("خلاصه تحلیل")).toBeInTheDocument());
    fireEvent.click(screen.getByText("خلاصه تحلیل"));
    await waitFor(() => expect(screen.getByText("اقدامی لازم نیست.")).toBeInTheDocument());
    fireEvent.click(screen.getByText("⟳ تحلیل مجدد"));
    await waitFor(() =>
      expect(mockedApi.post).toHaveBeenCalledWith("/api/admin/v1/ai-analyses/34/reanalyze"),
    );
  });

  it("keeps rendering alerts when the analyses endpoint fails", async () => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/alerts")) return { items: [ALERT], total: 1 };
      throw new apiModule.ApiError(500, "AI backend down");
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("SURICATA TLS Obsolete Version")).toBeInTheDocument());
    expect(screen.getByText("وضعیت تحلیل نامشخص")).toBeInTheDocument();
  });

  it("shows OFF and not analyzed; manual request targets only the chosen stable ID", async () => {
    mockBackend({ analyses: [] });
    renderPage();
    await screen.findByText("تحلیل نشده");
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");
    fireEvent.click(screen.getByRole("button", { name: "تحلیل با هوش مصنوعی هشدار 34" }));
    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith("/api/admin/v1/ai-analyses/34/analyze"));
    expect(mockedApi.post).toHaveBeenCalledTimes(1);
    expect(mockedApi.put).not.toHaveBeenCalled();
  });

  it("persists a toggle through the authenticated backend endpoint", async () => {
    mockBackend({ analyses: [] });
    mockedApi.put.mockImplementation(async () => {
      mockedApi.get.mockImplementation(async (path) => {
        if (path === "/api/admin/v1/security-ai") return { ...STATUS, auto_enabled: true };
        if (path.startsWith("/api/alerts")) return { items: [ALERT], total: 1 };
        return { items: [] };
      });
      return { auto_enabled: true };
    });
    renderPage();
    await screen.findByText("خاموش — OFF");
    fireEvent.click(screen.getByRole("switch"));
    await screen.findByText("روشن — ON");
    expect(mockedApi.put).toHaveBeenCalledWith("/api/admin/v1/security-ai/automatic", { enabled: true });
  });

  it.each(["PENDING", "PROCESSING", "COMPLETED"])("opens existing %s job without another Analyze request", async (status) => {
    mockBackend({ analyses: [{ alert_id: 34, status, job_id: "existing-job", summary: "خلاصه" }] });
    renderPage();
    const button = await screen.findByRole("button", { name: "تحلیل با هوش مصنوعی هشدار 34" });
    fireEvent.click(button);
    await screen.findByText("job_id=existing-job");
    expect(mockedApi.post).not.toHaveBeenCalled();
  });

  it("shows model errors and allows retry after failed analysis", async () => {
    mockBackend({ analyses: [{ alert_id: 34, status: "FAILED", error: "LLMTimeout", attempts: 3 }] });
    renderPage();
    await screen.findByText("تلاش دوباره");
    fireEvent.click(screen.getByText("تلاش دوباره"));
    await waitFor(() => expect(mockedApi.post).toHaveBeenCalledWith("/api/admin/v1/ai-analyses/34/analyze"));
  });

  it("does not show a successful toggle when the API rejects it", async () => {
    mockBackend({ analyses: [] });
    mockedApi.put.mockRejectedValue(new apiModule.ApiError(401, "دسترسی نامعتبر"));
    renderPage();
    await screen.findByText("خاموش — OFF");
    fireEvent.click(screen.getByRole("switch"));
    await screen.findByText("دسترسی نامعتبر");
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText(ALERT.signature)).toBeInTheDocument();
  });
});
