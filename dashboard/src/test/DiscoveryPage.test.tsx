import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { Mocked } from "vitest";
import DiscoveryPage from "../pages/Discovery";
import * as apiModule from "../lib/api";
import { MemoryRouter } from "react-router-dom";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn() },
  };
});

const mockedApi = apiModule.api as unknown as Mocked<typeof apiModule.api>;

function makeNetworksResponse(over: Partial<Record<string, unknown>> = {}) {
  return {
    observations: [],
    effective_scope: {
      configured_cidrs: [],
      authorized_targets: [],
      auto_discovered: [],
      auto_discovery_enabled: false,
      note: "…",
    },
    ...over,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <DiscoveryPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockedApi.get.mockImplementation(async (path: string) => {
    if (path.startsWith("/api/admin/v1/networks")) return makeNetworksResponse();
    if (path.startsWith("/api/hosts")) return { items: [] };
    if (path.startsWith("/api/admin/v1/agents")) return { items: [] };
    throw new Error(`unexpected path ${path}`);
  });
});

describe("DiscoveryPage", () => {
  it("reports failed host loading rather than displaying an empty topology and retries", async () => {
    const original = mockedApi.get.getMockImplementation()!;
    mockedApi.get.mockImplementation(async (path, options) => {
      if (path.startsWith("/api/hosts")) throw new apiModule.ApiError(503, "فهرست میزبان‌ها در دسترس نیست");
      return original(path, options);
    });
    renderPage();
    await screen.findByText("فهرست میزبان‌ها در دسترس نیست");
    expect(screen.queryByText("شبکه‌ای ثبت نشده")).not.toBeInTheDocument();
    mockedApi.get.mockImplementation(original);
    fireEvent.click(screen.getByRole("button", { name: "تلاش دوباره" }));
    await screen.findByText("شبکه‌ای ثبت نشده");
    expect(mockedApi.post).not.toHaveBeenCalled();
  });

  it("renders the empty state when observations are empty (scenario 1)", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("شبکه‌ای ثبت نشده")).toBeInTheDocument());
    expect(screen.getByText("کشف خودکار غیرفعال است")).toBeInTheDocument();
  });

  it("lists observed subnets from observations (scenario 2)", async () => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/admin/v1/networks")) {
        return makeNetworksResponse({
          observations: [
            { id: 1, agent_id: "agt_1", interface: "wlo1", cidr: "192.168.1.0/24",
              classification: "physical", connected: 1, source: "agent",
              first_seen: "2026-11-01T10:00:00+00:00", last_seen: "2026-11-01T11:00:00+00:00" },
          ],
        });
      }
      if (path.startsWith("/api/hosts")) return { items: [] };
      if (path.startsWith("/api/admin/v1/agents")) return { items: [] };
      throw new Error("unexpected");
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("192.168.1.0/24").length).toBeGreaterThan(0));
    // observed but not in the configured/authorized set → view-only badge
    expect(screen.getByText("فقط مشاهده")).toBeInTheDocument();
  });

  it("marks an observed subnet as authorized when the policy includes it (scenario 3)", async () => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/admin/v1/networks")) {
        return makeNetworksResponse({
          observations: [
            { id: 1, agent_id: "agt_1", interface: "eth0", cidr: "10.20.0.0/24",
              classification: "physical", connected: 1, source: "agent",
              first_seen: "x", last_seen: "y" },
          ],
          effective_scope: {
            configured_cidrs: ["10.20.0.0/24"],
            authorized_targets: [],
            auto_discovered: [],
            auto_discovery_enabled: true,
          },
        });
      }
      if (path.startsWith("/api/hosts")) return { items: [] };
      if (path.startsWith("/api/admin/v1/agents")) return { items: [] };
      throw new Error("unexpected");
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("مجاز")).toBeInTheDocument());
  });

  it.each([[401, "توکن"], [403, ""], [500, ""]])(
    "shows the error state on API %i instead of crashing (scenario 4)",
    async (status) => {
      mockedApi.get.mockImplementation(async (path: string) => {
        if (path.startsWith("/api/admin/v1/networks")) {
          throw new apiModule.ApiError(status, `API ${status}`);
        }
        if (path.startsWith("/api/hosts")) return { items: [] };
        return { items: [] };
      });
      renderPage();
      await waitFor(() => expect(screen.getByText(`API ${status}`)).toBeInTheDocument());
    },
  );

  it("shows a connection-lost error when the API is unreachable (scenario 5)", async () => {
    mockedApi.get.mockRejectedValue(new apiModule.ApiError(0, "ارتباط با هسته‌ی مرکزی برقرار نشد."));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("ارتباط با هسته‌ی مرکزی برقرار نشد.")).toBeInTheDocument(),
    );
  });

  it("does not crash on an invalid response shape", async () => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/admin/v1/networks")) return { unexpected: true };
      return { items: [] };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/فاقد observations/)).toBeInTheDocument());
  });

  it.each(["stale", "revoked"])("does not mark a %s agent as an online topology endpoint", async (status) => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/admin/v1/networks")) return makeNetworksResponse({
        observations: [{ agent_id: "agt_1", interface: "eth0", cidr: "192.0.2.0/24", connected: 1, classification: "physical" }],
      });
      if (path.startsWith("/api/hosts")) return { items: [{ ip: "192.0.2.42", hostname: "test-host" }] };
      if (path.startsWith("/api/admin/v1/agents")) return { items: [{ id: "agt_1", status, claimed_ips: ["192.0.2.42"] }] };
      throw new Error(`unexpected path ${path}`);
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("192.0.2.42").length).toBeGreaterThan(0));
    expect(document.querySelector(".badge-ok .pulse")).toBeNull();
  });

  it("renders hosts inside a subnet in the topology via real CIDR matching (scenarios 6-8)", async () => {
    mockedApi.get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/admin/v1/networks")) {
        return makeNetworksResponse({
          observations: [
            { id: 1, agent_id: "agt_1", interface: "wlo1", cidr: "10.233.68.0/24",
              classification: "physical", connected: 1, source: "agent", first_seen: "a", last_seen: "b" },
            { id: 2, agent_id: "agt_1", interface: "wlo1", cidr: "fe80::/64",
              classification: "physical", connected: 1, source: "agent", first_seen: "a", last_seen: "b" },
          ],
        });
      }
      if (path.startsWith("/api/hosts")) {
        return {
          items: [
            { ip: "10.233.68.48", hostname: "dev", mac: null, first_seen: null, last_seen: null },
            { ip: "10.233.69.99", hostname: "outside", mac: null, first_seen: null, last_seen: null },
            { ip: "fe80::abcd", hostname: "v6-host", mac: null, first_seen: null, last_seen: null },
          ],
        };
      }
      return { items: [] };
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("10.233.68.48").length).toBeGreaterThan(0));
    // outside-subnet host must NOT appear inside the /24 topology card
    const cardText = document.body.textContent ?? "";
    expect(cardText).toContain("fe80::abcd");
  });
});
