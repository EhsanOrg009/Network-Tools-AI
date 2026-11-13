import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "../App";
import { getToken, setToken } from "../lib/api";

beforeEach(() => {
  localStorage.clear();
  document.documentElement.setAttribute("data-theme", "dark");
  vi.stubGlobal("fetch", vi.fn(async (path: string) => {
    const data = path.includes("security-ai") ? {
      auto_enabled: false, counts: { PENDING: 0, PROCESSING: 0, COMPLETED: 0, FAILED: 0 },
      connection: { ok: true, detail: "ready" }, worker_enabled: true, model: "test-model",
    } : path.includes("/api/alerts") ? { items: [], total: 0, severity_counts: [] } : { ok: true };
    return new Response(JSON.stringify(data));
  }));
});
afterEach(() => vi.unstubAllGlobals());

function shell() {
  return render(<MemoryRouter initialEntries={["/dashboard/security"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><App /></MemoryRouter>);
}

it("logs in through the backend, retains every navigation route, and logs out without a reload", async () => {
  shell();
  fireEvent.change(screen.getByLabelText("توکن دسترسی مدیر"), { target: { value: "test-admin-token" } });
  fireEvent.click(screen.getByRole("button", { name: "ورود به داشبورد" }));
  await screen.findByRole("switch");
  expect(getToken()).toBe("test-admin-token");
  const nav = screen.getByRole("navigation", { name: "ناوبری اصلی" });
  expect(nav.querySelectorAll("a")).toHaveLength(10);
  expect(screen.getByRole("link", { name: "مرکز امنیت" })).toHaveAttribute("aria-current", "page");
  fireEvent.click(screen.getByRole("button", { name: "تغییر پوسته" }));
  await waitFor(() => expect(document.documentElement).toHaveAttribute("data-theme", "light"));
  fireEvent.click(screen.getByRole("button", { name: "خروج از داشبورد" }));
  await screen.findByLabelText("توکن دسترسی مدیر");
  expect(getToken()).toBe("");
});

it("shows the rejected login message and leaves no authenticated shell", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"detail":"توکن نامعتبر است"}', { status: 401 })));
  shell();
  fireEvent.change(screen.getByLabelText("توکن دسترسی مدیر"), { target: { value: "invalid-token" } });
  fireEvent.click(screen.getByRole("button", { name: "ورود به داشبورد" }));
  await screen.findByRole("alert");
  expect(screen.getByText("توکن نامعتبر است")).toBeInTheDocument();
  expect(getToken()).toBe("");
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
});

it("closes mobile navigation on Escape and exposes all operations", async () => {
  setToken("test-admin-token");
  shell();
  await screen.findByRole("switch");
  const menu = screen.getByRole("button", { name: "بازکردن منوی ناوبری" });
  fireEvent.click(menu);
  expect(menu).toHaveAttribute("aria-expanded", "true");
  fireEvent.keyDown(document, { key: "Escape" });
  expect(menu).toHaveAttribute("aria-expanded", "false");
});

it("finds an operational page through the keyboard navigator without submitting jobs", async () => {
  setToken("test-admin-token");
  shell();
  await screen.findByRole("switch");
  fireEvent.keyDown(document, { key: "k", ctrlKey: true });
  const dialog = await screen.findByRole("dialog");
  const search = within(dialog).getByLabelText("جست‌وجوی صفحه‌ها");
  fireEvent.change(search, { target: { value: "SECURITY" } });
  expect(within(dialog).getAllByRole("button")).toHaveLength(2);
  fireEvent.keyDown(search, { key: "Enter" });
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("switch")).toBeInTheDocument();
  expect(vi.mocked(fetch).mock.calls.every(([, options]) => options?.method === "GET")).toBe(true);
});
