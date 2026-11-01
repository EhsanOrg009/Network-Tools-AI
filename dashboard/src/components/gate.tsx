/** Token-gate screen: the dashboard operator pastes the ADMIN_API_TOKEN once.
 *  It lives only in the browser's localStorage and is sent as Bearer. */

import { useState } from "react";
import { api, setToken, hasToken } from "../lib/api";
import { IconShield, IconOff } from "./icons";

export function TokenGate() {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // unused import guard
  void hasToken;

  async function submit() {
    setBusy(true);
    setError(null);
    const candidate = value.trim();
    setToken(candidate);
    try {
      await api.get("/api/dashboard/v1/healthz");
      window.location.reload();
    } catch (e) {
      setToken("");
      setError(
        (e instanceof Error && e.message) || "توکن پذیرفته نشد.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="card card-pad" style={{ width: "min(460px, 92vw)" }}>
      <div className="row" style={{ gap: 12, marginBottom: 14 }}>
        <div className="stat-icon" style={{ background: "var(--accent-soft)", color: "var(--accent)" }}>
          <IconShield size={20} />
        </div>
        <div>
          <h2 style={{ fontSize: 17 }}>ورود به داشبورد مدیریتی</h2>
          <div className="small muted">احراز هویت روی هسته‌ی مرکزی انجام می‌شود، نه در این صفحه.</div>
        </div>
      </div>
      <label className="field-label" htmlFor="admin-token">توکن مدیر (ADMIN_API_TOKEN)</label>
      <input
        id="admin-token"
        className="input technical"
        type="password"
        dir="ltr"
        placeholder="ADMIN_API_TOKEN"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && submit()}
        autoFocus
      />
      {error && (
        <div className="small" style={{ color: "var(--danger)", marginTop: 10 }}>
          <IconOff size={13} /> {error}
        </div>
      )}
      <div className="row" style={{ marginTop: 16, gap: 8 }}>
        <button className="btn primary" disabled={busy || !value.trim()} onClick={submit}>
          {busy ? "در حال بررسی…" : "ورود"}
        </button>
        <a className="btn ghost" href="/api/docs" target="_blank" rel="noreferrer">مستندات API ↗</a>
      </div>
      <div className="divider" />
      <div className="small muted" style={{ lineHeight: 1.9 }}>
        توکن مدیر از متغیر محیطی <code className="technical">ADMIN_API_TOKEN</code> هسته‌ی مرکزی
        تعیین می‌شود. مدل هوش مصنوعی به این توکن و مسیرهای مدیریتی دسترسی ندارد.
      </div>
    </div>
  );
}

export { TokenGate as default, TokenGate as Buttonish };
