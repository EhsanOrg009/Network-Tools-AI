import { useState } from "react";
import { api, setToken } from "../lib/api";
import { IconShield, IconNodes, IconCheck } from "./icons";
import { useTheme } from "../lib/theme";
import { MiniSpinner } from "./ui";

export function TokenGate() {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { theme, toggle } = useTheme();

  async function submit() {
    if (busy || !value.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.get("/api/dashboard/v1/healthz", { token: value.trim() });
      setToken(value);
    } catch (e) {
      setError(e instanceof Error ? e.message : "توکن پذیرفته نشد.");
    } finally { setBusy(false); }
  }

  return <div className="login-screen">
    <section className="login-intro">
      <div className="brand">
        <span className="brand-logo"><IconNodes size={24} /></span>
        <span className="brand-text"><b dir="ltr">NetAgent<span className="brand-period">.</span></b><small>مرکز عملیات شبکه</small></span>
      </div>
      <div className="eyebrow">NETWORK INTELLIGENCE</div>
      <h1>دید روشن‌تر به شبکه.<br />کنترل دقیق‌تر بر امنیت.</h1>
      <p>پایش نقاط پایانی، بررسی رویدادهای امنیتی و هوش مصنوعی محلی در یک فضای کاری یکپارچه.</p>
      <div className="login-features"><span><IconCheck size={14} />تحلیل محلی</span><span><IconCheck size={14} />تصمیم با مدیر</span><span><IconCheck size={14} />ثبت حسابرسی</span></div>
      <svg className="login-visual" viewBox="0 0 440 145" aria-hidden="true" fill="none">
        <path d="M24 28H118L184 72H270L330 26H416M24 118H116L184 72M270 72L330 118H416" stroke="#36535e" />
        <path d="M184 72H270" stroke="#5ad6b7" />
        {[24, 118, 184, 270, 330, 416].map((x, i) => <g key={x}>
          <rect x={x - 12} y={(i === 2 || i === 3 ? 72 : 28) - 12} width="24" height="24" rx="6" fill="#17282e" stroke="#45606b" />
          <circle cx={x} cy={i === 2 || i === 3 ? 72 : 28} r="3" fill="#5ad6b7" />
        </g>)}
        <circle cx="24" cy="118" r="5" fill="#283c45" stroke="#45606b" />
        <circle cx="330" cy="118" r="5" fill="#283c45" stroke="#45606b" />
        <circle cx="416" cy="118" r="5" fill="#283c45" stroke="#45606b" />
      </svg>
    </section>
    <section className="login-form-region">
      <form className="login-form" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <div className="stat-icon" style={{ width: 44, height: 44 }}><IconShield size={22} /></div>
        <h2>ورود به فضای مدیریت</h2>
        <p className="small muted" style={{ marginBottom: 30 }}>با توکن مدیر به هستهٔ مرکزی متصل شوید.</p>
        <label className="field-label" htmlFor="admin-token">توکن دسترسی مدیر</label>
        <input id="admin-token" className="input technical" type="password" dir="ltr" placeholder="ADMIN_API_TOKEN"
          autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} disabled={busy} autoFocus required />
        {error && <div className="login-error" role="alert">{error}</div>}
        <button type="submit" className="btn primary" disabled={busy || !value.trim()}>{busy ? <><MiniSpinner />در حال بررسی…</> : "ورود به داشبورد"}</button>
        <div className="divider" />
        <div className="row wrap" style={{ justifyContent: "space-between" }}>
          <a href="/api/docs" target="_blank" rel="noreferrer" className="small">مستندات API ↗</a>
          <button type="button" className="btn ghost sm" onClick={toggle}>{theme === "dark" ? "پوستهٔ روشن" : "پوستهٔ تیره"}</button>
        </div>
        <p className="small muted" style={{ marginTop: 22, lineHeight: 2 }}>توکن فقط در این مرورگر ذخیره می‌شود. احراز هویت توسط هسته انجام می‌شود؛ مدل به اعتبارنامهٔ مدیر دسترسی ندارد.</p>
      </form>
    </section>
  </div>;
}

export { TokenGate as default, TokenGate as Buttonish };
