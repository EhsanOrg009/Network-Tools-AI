import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import AgentDetailPage from "../pages/AgentDetail";
import { api } from "../lib/api";

vi.mock("../lib/api", () => ({ api: { get: vi.fn(), post: vi.fn() } }));

it("discards an old endpoint response when navigation opens a different endpoint", async () => {
  let release!: (value: unknown) => void;
  const old = new Promise((resolve) => { release = resolve; });
  vi.mocked(api.get).mockImplementation(async (path) => {
    if (path.includes("/agents/first?")) return old;
    if (path.includes("/agents/second?")) return { agent: { id: "second", hostname: "current-endpoint", status: "active", capabilities: [] } };
    return { items: [] };
  });
  render(<MemoryRouter initialEntries={["/dashboard/agents/first"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
    <Link to="/dashboard/agents/second">عامل بعدی</Link>
    <Routes><Route path="/dashboard/agents/:agentId" element={<AgentDetailPage />} /></Routes>
  </MemoryRouter>);
  await waitFor(() => expect(api.get).toHaveBeenCalled());
  fireEvent.click(screen.getByText("عامل بعدی"));
  await screen.findByText("current-endpoint");
  await act(async () => { release({ agent: { id: "first", hostname: "stale-endpoint", status: "active", capabilities: [] } }); });
  expect(screen.queryByText("stale-endpoint")).not.toBeInTheDocument();
  expect(screen.getByText("current-endpoint")).toBeInTheDocument();
});
