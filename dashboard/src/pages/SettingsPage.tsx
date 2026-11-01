/**
 * Settings: server configuration view (non-secret, admin-authenticated) +
 * dashboard-side preferences. Secret values are NEVER requested or shown —
 * the backend decides what is safe to export.
 */

import { useCallback, useEffect, useState } from "react";
import { api, getToken, setToken as storeToken } from "../lib/api";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/ui";
import { useToast } from "../components/toast";
import { useTheme } from "../lib/theme";
import { IconGear, IconShield } from "../components/icons";

interface ServerSettings {
  [k: string]: string | number | boolean | null;
}

export default function SettingsPage() {
  const [server, setServer] = useState<ServerSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tokenInput, setTokenInput] = useState("");
  const { theme, toggle } = useTheme();
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      setError(null);
      const d = await api.get<ServerSettings>("/api/dashboard/v1/settings");
      setServer(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  function saveToken() {
    storeToken(tokenInput.trim());
    toast.push(tokenInput.trim() ? "توکن داشبورد در این مرورگر به‌روزرسانی شد." : "توکن پاک شد؛ برای ادامه دوباره وارد کنید.", "success");
    setTokenInput("");
  }

  const SECTIONS: { title: string; keys: string[] }[] = [
    { title: "اتصال و پوشش", keys: ["app_host", "app_port", "monitor_cidrs", "authorized_targets"] },
    { title: "کشف شبکه", keys: ["discovery_excluded_cidrs", "discovery_excluded_interfaces", "auto_discovery_max_addresses", "auto_discovery_min_reporters"] },
    { title: "عامل‌ها و ثبت‌نام", keys: ["allow_auto_registration", "enrollment_request_ttl_minutes", "max_pending_enrollment_requests", "registration_rate_limit_per_hour", "agent_heartbeat_interval_seconds", "agent_heartbeat_timeout_seconds", "agent_inventory_interval_seconds"] },
    { title: "کنسول و امنیت", keys: ["allow_admin_python_console", "console_session_ttl_minutes", "console_idle_timeout_seconds", "console_command_timeout_seconds", "console_max_output_bytes"] },
    { title: "مدل هوش مصنوعی", keys: ["llm_enabled", "llm_base_url", "llm_model"] },
    { title: "مانیتورینگ", keys: ["suricata_eve_path", "enable_monitor"] },
  ];

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconGear size={20} style={{ color: "var(--accent)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>تنظیمات</div>
            <div className="small muted">
              پیکربندی هسته از متغیرهای محیطی (<code className="technical">.env</code>) می‌آید؛ این
              صفحه فقط خواندنی است و مقادیر حساس (توکن‌ها و کلیدها) هرگز نمایش داده نمی‌شوند.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => void load()}>↻ به‌روزرسانی</button>
        </div>
      </div>

      <div className="grid-half">
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {server === null && !error ? <div className="card card-pad"><SkeletonRows rows={6} /></div>
            : error ? (
              <div className="card">
                <ErrorState message={`${error} — تلاش دوباره پس از تعریف اندپوینت تنظیمات؟`} onRetry={() => void load()} />
              </div>
            )
              : !server ? <EmptyState title="تنظیمات خالی" />
                : SECTIONS.map((sec) => {
                  const rows = sec.keys.filter((k) => k in server);
                  if (rows.length === 0) return null;
                  return (
                    <Card key={sec.title} title={sec.title} pad={false}>
                      <div className="table-wrap">
                        <table className="data">
                          <tbody>
                            {rows.map((k) => {
                              const v = server[k];
                              return (
                                <tr key={k}>
                                  <td className="technical small" style={{ color: "var(--text-2)", width: "54%" }}>{k}</td>
                                  <td className="technical small">{typeof v === "boolean" ? (v ? "فعال" : "غیرفعال") : String(v)}</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  );
                })}
          {!server && !error && <EmptyState title="اندپوینت پیکربندی هنوز فعال نیست" />}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <Card title="نمایش داشبورد">
            <dl className="two-col-defs">
              <dt>پوسته</dt>
              <dd>
                <button className="btn sm" onClick={toggle}>{theme === "dark" ? "تغییر به روشن" : "تغییر به تیره"}</button>
              </dd>
              <dt>منطقه‌ی زمانی</dt><dd>Asia/Tehran (تاریخ شمسی)</dd>
              <dt>زبان رابط</dt><dd>فارسی — RTL</dd>
              <dt>به‌روزرسانی داده</dt><dd>Polling بهینه (۲۰ ثانیه)</dd>
            </dl>
          </Card>

          <Card title="اتصال این مرورگر به هسته" extra={<IconShield size={15} style={{ color: "var(--ok)" }} />}>
            <div className="small muted" style={{ lineHeight: 1.9 }}>
              توکن فعلی: <span className="code-chip">{getToken() ? "••••••••(نمایش داده نمی‌شود)" : "—"}</span>
              <br />احراز هویت در Backend انجام می‌شود؛ پنهان کردن دکمه‌ها در امنیت نقش ندارد.
            </div>
            <div style={{ marginTop: 12 }}>
              <label className="field-label" htmlFor="token-input">جایگزینی توکن مدیر</label>
              <div className="row">
                <input
                  id="token-input"
                  className="input technical"
                  dir="ltr"
                  type="password"
                  placeholder="ADMIN_API_TOKEN"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                />
                <button className="btn sm" disabled={!tokenInput.trim()} onClick={saveToken}>ذخیره</button>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
