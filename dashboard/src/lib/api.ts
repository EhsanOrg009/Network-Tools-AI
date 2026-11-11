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
    super(detail);
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
  window.dispatchEvent(new Event("netagent-auth"));
}

export function subscribeAuth(listener: () => void) {
  window.addEventListener("netagent-auth", listener);
  window.addEventListener("storage", listener);
  return () => {
    window.removeEventListener("netagent-auth", listener);
    window.removeEventListener("storage", listener);
  };
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
    if (res.ok) throw new ApiError(res.status, "پاسخ هسته قالب JSON معتبر ندارد.");
    return { detail: text };
  }
}

interface RequestOptions { token?: string; signal?: AbortSignal }

async function request<T>(method: string, path: string, body?: unknown, options?: RequestOptions): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = options?.token ?? getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: options?.signal,
    });
  } catch (e) {
    if (options?.signal?.aborted) throw e;
    throw new ApiError(0, "ارتباط با هسته‌ی مرکزی برقرار نشد.");
  }
  const data = await parseBody(res);
  if (!res.ok) {
    if (res.status === 401 && options?.token === undefined && token && token === getToken()) setToken("");
    const rawDetail = data && typeof data === "object" && "detail" in data ? (data as Record<string, unknown>).detail : null;
    const detail =
      rawDetail
        ? Array.isArray(rawDetail) ? rawDetail.map((item) => typeof item === "object" && item && "msg" in item ? String(item.msg) : JSON.stringify(item)).join("؛ ") : String(rawDetail)
        : `خطای ناشناخته (کد ${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>("GET", path, undefined, options),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
};
