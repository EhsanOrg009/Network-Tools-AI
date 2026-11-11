import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import AgentsPage from "../pages/Agents";
import { ToastProvider } from "../components/toast";

vi.mock("../lib/api", () => ({ api: { get: vi.fn(async () => ({ items: [
  { id: "agt_windows", hostname: "windows-host", platform: "Windows", status: "active", claimed_ips: [] },
  { id: "agt_linux", hostname: "linux-host", platform: "Linux", status: "active", claimed_ips: [] },
] })) } }));

it("sorts operating systems as text in both directions", async () => {
  const { container } = render(<MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><ToastProvider><AgentsPage /></ToastProvider></MemoryRouter>);
  await screen.findByText("windows-host");
  fireEvent.click(screen.getByRole("button", { name: "سیستم‌عامل ↕" }));
  expect(container.querySelector("tbody tr")?.textContent).toContain("linux-host");
  fireEvent.click(screen.getByRole("button", { name: "سیستم‌عامل ↕" }));
  expect(container.querySelector("tbody tr")?.textContent).toContain("windows-host");
});
