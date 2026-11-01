/**
 * API client: every call goes to the real FastAPI backend — no mocks, no DOM
 * scraping. The admin token lives in localStorage only (entered once by the
 * dashboard operator) and is sent as `Authorization: Bearer`.
 */

const STORAGE_KEY = "netagent.admin_token";

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`API ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

export function getToken(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  const trimmed = token.trim();
  if (trimmed) localStorage.setItem(STORAGE_KEY, trimmed);
  else localStorage.removeItem(STORAGE_KEY);
}

export function hasToken(): boolean {
  return getToken().length > 0;
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { detail: text };
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "ارتباط با هسته‌ی مرکزی برقرار نشد.");
  }
  const data = await parseBody(res);
  if (!res.ok) {
    const detail =
      (data && typeof data === "object" && "detail" in data)
        ? String((data as Record<string, unknown>).detail)
        : `خطای ناشناخته (کد ${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
};
