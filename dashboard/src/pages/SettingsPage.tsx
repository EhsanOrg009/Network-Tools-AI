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
import type { AuditRow } from "../lib/types";
import { faNum, fmtDateTime } from "../lib/format";

interface ServerSettings {
  [k: string]: string | number | boolean | null;
}

export default function SettingsPage() {
  const [server, setServer] = useState<ServerSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tokenInput, setTokenInput] = useState("");
  const [tokenBusy, setTokenBusy] = useState(false);
  const [audit, setAudit] = useState<AuditRow[] | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
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

  const loadAudit = useCallback(async () => {
    setAuditError(null);
    try { setAudit((await api.get<{ items: AuditRow[] }>("/api/admin/v1/audit?limit=50")).items); }
    catch (e) { setAuditError(e instanceof Error ? e.message : "دریافت حسابرسی ناموفق بود."); }
  }, []);
  useEffect(() => { void loadAudit(); }, [loadAudit]);

  async function saveToken() {
    if (tokenBusy || !tokenInput.trim()) return;
    setTokenBusy(true);
    try {
      await api.get("/api/dashboard/v1/healthz", { token: tokenInput.trim() });
      storeToken(tokenInput);
      toast.push("توکن معتبر در این مرورگر به‌روزرسانی شد.", "success");
      setTokenInput("");
    } catch (e) { toast.push(e instanceof Error ? e.message : "توکن پذیرفته نشد.", "error"); }
    finally { setTokenBusy(false); }
  }

  const SECTIONS: { title: string; keys: string[] }[] = [
    { title: "اتصال و پوشش", keys: ["app_host", "app_port", "monitor_cidrs", "authorized_targets"] },
    { title: "کشف شبکه", keys: ["discovery_excluded_cidrs", "discovery_excluded_interfaces", "auto_discovery_max_addresses", "auto_discovery_min_reporters"] },
    { title: "عامل‌ها و ثبت‌نام", keys: ["allow_auto_registration", "enrollment_request_ttl_minutes", "max_pending_enrollment_requests", "registration_rate_limit_per_hour", "agent_heartbeat_interval_seconds", "agent_heartbeat_timeout_seconds", "agent_inventory_interval_seconds"] },
    { title: "کنسول و امنیت", keys: ["allow_admin_python_console", "console_session_ttl_seconds", "console_idle_timeout_seconds", "console_command_timeout_seconds", "console_max_output_bytes"] },
    { title: "مدل هوش مصنوعی", keys: ["llm_enabled", "llm_base_url", "llm_model", "llm_timeout_seconds", "llm_max_output_tokens", "llm_structured_outputs"] },
    { title: "ظرفیت تحلیل و کارهای پس‌زمینه", keys: ["ai_analysis_enabled", "ai_analysis_backlog_limit", "ai_analysis_intake_limit", "ai_analysis_batch_size", "job_workers", "job_queue_size"] },
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
                <ErrorState message={error} onRetry={() => void load()} />
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
              <dt>به‌روزرسانی داده</dt><dd>بررسی اتصال هر ۲۰ ثانیه؛ صفحات زنده با فاصلهٔ مشخص خود</dd>
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
                <button className="btn sm" disabled={tokenBusy || !tokenInput.trim()} onClick={() => void saveToken()}>{tokenBusy ? "بررسی…" : "ذخیره"}</button>
              </div>
            </div>
          </Card>
        </div>
      </div>
      <section id="audit-records" className="section-gap">
        <Card pad={false} title="حسابرسی عملیات" extra={<button className="btn sm" onClick={() => void loadAudit()}>↻ به‌روزرسانی حسابرسی</button>}>
          {auditError ? <ErrorState message={auditError} onRetry={() => void loadAudit()} /> : audit === null ? <SkeletonRows />
            : audit.length === 0 ? <EmptyState title="عملیاتی ثبت نشده" hint="تغییر تنظیم خودکار و درخواست‌های تحلیل تکی در اینجا ثبت می‌شوند." />
            : <div className="table-wrap"><table className="data"><thead><tr><th>زمان</th><th>کنش</th><th>عامل عملیات</th><th>هدف</th></tr></thead><tbody>
              {audit.map((entry, i) => <tr key={i}><td>{fmtDateTime(entry.at)}</td><td className="technical">{entry.action}</td><td>{entry.actor}</td><td className="technical">{entry.target ?? "—"}</td></tr>)}
            </tbody></table></div>}
          {audit && <p className="small muted" style={{ padding: "12px 20px" }}>آخرین {faNum(audit.length)} عملیات؛ ثبت حسابرسی توسط هسته انجام می‌شود.</p>}
        </Card>
      </section>
    </div>
  );
}
