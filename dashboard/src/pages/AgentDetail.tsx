/**
 * Per-agent detail page: `/dashboard/agents/{agent_id}`.
 * Tabs: System / Network / Activity / Diagnostics / Console / Management.
 * All sections label the data SOURCE (agent-declared vs core-derived).
 */

import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../lib/api";
import type { AgentSummary, InventoryData, TaskRow, AuditRow } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime, fmtSeconds } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, StatusPill, TechChip, ConfirmDialog } from "../components/ui";
import { IconAgents, IconHeartbeat } from "../components/icons";
import { useToast } from "../components/toast";
import RemoteConsole from "../components/RemoteConsole";

const TASK_TYPE_FA: Record<string, string> = {
  inventory_collection: "فهرست‌برداری سیستم و شبکه",
  connectivity_diagnostic: "تست اتصال/connectivity",
  service_inventory: "فهرست سرویس‌ها",
  network_configuration: "پیکربندی شبکه",
  approved_network_diagnostic: "تست شبکه‌ی مجاز",
  admin_python_script: "اسکریپت پایتون مدیریتی",
  console_session: "نشست کنسول",
  console_command: "دستور کنسول",
  console_terminate: "بستن نشست کنسول",
};

interface AgentBundle {
  agent: AgentSummary;
  inventory?: { collected_at?: string; inventory?: InventoryData; [k: string]: unknown } | null;
  inventory_history?: { collected_at: string }[];
}

export default function AgentDetailPage() {
  const { agentId = "" } = useParams();
  const [bundle, setBundle] = useState<AgentBundle | null>(null);
  const [tasks, setTasks] = useState<TaskRow[] | null>(null);
  const [audit, setAudit] = useState<AuditRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"system" | "network" | "activity" | "diagnostics" | "console" | "manage">("system");
  const [refreshKey, setRefresh] = useState(0);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [busyTask, setBusyTask] = useState<string | null>(null);
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      setError(null);
      const d = await api.get<AgentBundle>(`/api/admin/v1/agents/${agentId}?inventory=true`);
      setBundle(d);
      const [t, a] = await Promise.all([
        api.get<{ items: TaskRow[] }>(`/api/admin/v1/tasks?agent_id=${agentId}&limit=50`),
        api.get<{ items: AuditRow[] }>("/api/admin/v1/audit?limit=300"),
      ]);
      setTasks(t.items);
      setAudit(a.items.filter((x) => (x.target ?? "").includes(agentId)).slice(0, 40));
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, [agentId]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  async function requestTask(type: string) {
    setBusyTask(type);
    try {
      const params =
        type === "connectivity_diagnostic"
          ? { target: "8.8.8.8" }
          : {};
      await api.post("/api/admin/v1/tasks", { agent_id: agentId, type, params });
      toast.push(`تسک «${TASK_TYPE_FA[type] ?? type}» در صف قرار گرفت؛ نتیجه با ضربان بعدی عامل می‌آید.`, "success");
      setRefresh((k) => k + 1);
    } catch (e) {
      toast.push(e instanceof Error ? `ساخت تسک ناموفق: ${e.message}` : "ساخت تسک ناموفق بود", "error");
    } finally {
      setBusyTask(null);
    }
  }

  if (error) {
    return (
      <div className="card">
        <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
        <div style={{ textAlign: "center", paddingBottom: 18 }}>
          <Link className="btn sm" to="/dashboard/agents">بازگشت به فهرست عامل‌ها</Link>
        </div>
      </div>
    );
  }
  if (!bundle) return <div className="card"><SkeletonRows rows={4} /></div>;

  const a = bundle.agent;
  const inv = (bundle.inventory as { inventory?: InventoryData } | null)?.inventory
    ?? (bundle.inventory as unknown as InventoryData | null);
  const invAt = bundle.inventory?.collected_at ?? a.latest_inventory_at;
  const healthAnyway = a.status === "active";

  const ifaces = inv?.interfaces ?? [];
  const sysRows: [string, unknown][] = [
    ["OS", `${(inv as { os_name?: string })?.os_name ?? "—"} ${(inv as { os_version?: string })?.os_version ?? ""}`.trim()],
    ["Kernel / Build", (inv as { kernel?: string })?.kernel ?? "—"],
    ["Architecture", (inv as { arch?: string })?.arch ?? "—"],
    ["Python", (inv as { python_version?: string })?.python_version ?? "—"],
    ["Hostname", inv?.hostname ?? a.hostname ?? "—"],
    ["Uptime", typeof (inv as { uptime_seconds?: number })?.uptime_seconds === "number"
      ? fmtSeconds((inv as { uptime_seconds?: number }).uptime_seconds!) : "—"],
    ["آخرین جمع‌آوری inventory", fmtDateTime(invAt)],
  ];

  return (
    <div>
      {/* header */}
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 14 }}>
          <div className="stat-icon" style={{ background: "var(--accent-soft)", color: "var(--accent)", width: 42, height: 42 }}>
            <IconAgents size={22} />
          </div>
          <div>
            <div className="row" style={{ gap: 10 }}>
              <h2 style={{ fontSize: 17 }}>{a.hostname ?? agentId}</h2>
              <StatusPill state={a.status} pulse={a.status === "active"} />
              <span className={`badge ${healthAnyway ? "badge-ok" : "badge-warn"}`} title="ارزیابی ساده بر پایه‌ی ضربان اخیر">
                <IconHeartbeat size={12} /> {healthAnyway ? "سلامت ارتباط خوب" : "ارتباط نامطمئن"}
              </span>
            </div>
            <div className="row small muted" style={{ gap: 10, marginTop: 3 }}>
              <TechChip>{a.id}</TechChip>
              <span>{a.platform ?? "—"} • نسخه عامل <span className="technical">{a.agent_version ?? "—"}</span></span>
            </div>
          </div>
          <div className="spacer" />
          <div className="small" style={{ textAlign: "end" }}>
            <div className="muted">آخرین ضربان</div>
            <div style={{ fontWeight: 700 }}>{fmtAgo(a.last_heartbeat_at)}</div>
            <div className="muted small">هر {fmtSeconds(a.heartbeat_interval_seconds)}</div>
          </div>
          <Link className="btn sm" to="/dashboard/agents">← فهرست</Link>
        </div>
      </div>

      {/* tabs */}
      <div className="tabs">
        {([
          ["system", "سیستم"], ["network", "شبکه"], ["activity", "فعالیت‌ها"],
          ["diagnostics", "عیب‌یابی"], ["console", "کنسول پایتون"], ["manage", "مدیریت"],
        ] as const).map(([k, label]) => (
          <button key={k} className={`tab${tab === k ? " active" : ""}`} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>

      {tab === "system" && (
        <div className="grid-half">
          <Card title="اطلاعات سیستم — منبع: inventory خود عامل">
            {inv ? (
              <>
                <dl className="two-col-defs">
                  {sysRows.map(([k, v]) => (
                    <span key={k as string} style={{ display: "contents" }}>
                      <dt>{k}</dt><dd className={typeof v === "string" && k !== "OS" ? "technical" : ""}>{String(v ?? "—")}</dd>
                    </span>
                  ))}
                </dl>
                <details style={{ marginTop: 14 }}>
                  <summary className="small muted" style={{ cursor: "pointer" }}>پیش‌نمایش کامل JSON</summary>
                  <pre className="code-block" style={{ marginTop: 8 }}>{JSON.stringify(inv, null, 2)}</pre>
                </details>
              </>
            ) : (
              <EmptyState title="هنوز inventoryی گزارش نشده"
                hint="با اولین ضربان پذیرفته‌شده، عامل اطلاعات سیستم را می‌فرستد." />
            )}
          </Card>
          <Card title="قابلیت‌های اعلامی و هویت">
            <div className="row wrap" style={{ gap: 8 }}>
              {(a.capabilities ?? []).map((c) => <span key={c} className="badge badge-accent technical">{c}</span>)}
              {!a.capabilities?.length && <span className="small muted">قابلیتی ثبت نشده.</span>}
            </div>
            <div className="divider" />
            <dl className="two-col-defs">
              <dt>ثبت‌نام</dt><dd>{fmtDateTime(a.enrolled_at)}</dd>
              <dt>آخرین inventory</dt><dd>{fmtDateTime(a.latest_inventory_at)}</dd>
              <dt>IPهای اعلامی (ضربان)</dt><dd className="technical small">{(a.claimed_ips ?? []).join(" ، ") || "—"}</dd>
              {a.revoked_at && (<><dt>باطل‌سازی</dt><dd>{fmtDateTime(a.revoked_at)}</dd></>)}
            </dl>
          </Card>
        </div>
      )}

      {tab === "network" && (
        <Card title="رابط‌های شبکه — منبع: inventory خود عامل" pad={false}>
          {ifaces.length === 0 ? (
            <EmptyState title="اطلاعات رابط شبکه موجود نیست" hint="بعد از inventory بعدی یا تسک network_configuration پر می‌شود." />
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>نام</th><th>نوع / دسته</th><th>وضعیت</th><th>MAC</th>
                    <th>آدرس‌ها</th><th>Prefix / Mask</th><th>Gateway</th><th>DNS</th>
                  </tr>
                </thead>
                <tbody>
                  {ifaces.map((i, ix) => (
                    <tr key={`${i.name}-${ix}`}>
                      <td className="technical">{i.name}</td>
                      <td className="small">{i.classification ? `${i.classification}${i.type ? ` / ${i.type}` : ""}` : i.type ?? "—"}</td>
                      <td>{i.up === true ? <span className="badge badge-ok">up</span> : i.up === false ? <span className="badge badge-muted">down</span> : "—"}</td>
                      <td className="technical small">{i.mac ?? "—"}</td>
                      <td className="technical small" style={{ maxWidth: 260 }}>
                        {[...(i.ipv4 ?? []), ...(i.ipv6 ?? [])].join(" ، ") || "—"}
                      </td>
                      <td className="technical small">{i.prefixlen != null ? `/${i.prefixlen}` : i.subnet_mask ?? "—"}</td>
                      <td className="technical small">{i.gateway ?? "—"}</td>
                      <td className="technical small">{(i.dns_servers ?? []).join(" ، ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="card-pad small muted">
            رابط‌های Virtual / VPN / Loopback از همان طبقه‌بندی‌ای می‌آیند که عامل گزارش کرده؛
            هسته فرض اضافه نمی‌کند.
          </div>
        </Card>
      )}

      {tab === "activity" && (
        <div className="grid-half">
          <Card title="تسک‌های این عامل" pad={false}>
            {tasks === null ? <SkeletonRows rows={4} /> : tasks.length === 0 ? (
              <EmptyState title="تسکی برای این عامل ثبت نشده" />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>نوع</th><th>وضعیت</th><th>ایجاد</th><th>زمان اجرا</th></tr></thead>
                  <tbody>
                    {tasks.map((t) => (
                      <tr key={t.id}>
                        <td>{TASK_TYPE_FA[t.type] ?? t.type}<div className="small muted technical">{t.id}</div></td>
                        <td><StatusPill state={t.status} /></td>
                        <td className="small muted">{fmtAgo(t.created_at)}</td>
                        <td className="small muted">{t.duration_ms != null ? `${faNum(Math.round(t.duration_ms))}ms` : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          <Card title="رخدادهای حسابرسی مرتبط با این دستگاه — منبع: audit هسته" pad={false}>
            {audit === null ? <SkeletonRows rows={4} /> : audit.length === 0 ? (
              <EmptyState title="رکورد حسابرسی مرتبطی نیست" />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>Action</th><th>Actor</th><th>Outcome</th><th>زمان</th></tr></thead>
                  <tbody>
                    {audit.map((x, i) => (
                      <tr key={i}>
                        <td className="code-chip" style={{ fontSize: 11 }}>{x.action}</td>
                        <td className="small">{x.actor}</td>
                        <td><span className={`badge ${x.outcome === "ok" ? "badge-ok" : "badge-warn"}`}>{x.outcome}</span></td>
                        <td className="small muted">{fmtDateTime(x.at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "diagnostics" && (
        <div className="grid-half">
          <Card title="درخواست تشخیص جدید">
            <div className="small muted" style={{ marginBottom: 12 }}>
              تسک‌های تشخیصی بدون امضا ارسال می‌شوند و عامل پس از پذیرش، نتیجه را با نتیجه‌ی
              همان تسک برمی‌گرداند. تسک‌های مدیریتی (کنسول/اسکریپت) از این‌جا ساخته نمی‌شوند.
            </div>
            <div className="row wrap" style={{ gap: 8 }}>
              {["inventory_collection", "connectivity_diagnostic", "service_inventory", "network_configuration", "approved_network_diagnostic"].map((t) => (
                <button key={t} className="btn sm" disabled={busyTask === t || a.status === "revoked"}
                  onClick={() => requestTask(t)}>
                  {busyTask === t ? "…" : `+ ${TASK_TYPE_FA[t] ?? t}`}
                </button>
              ))}
            </div>
          </Card>
          <Card title="نتایج قابل استناد — منبع: نتایج تسک پاس‌داده‌شده" pad={false}>
            {tasks !== null && tasks.some((t) => t.result && Object.keys(t.result).length && t.error === undefined) ? (
              <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
                {tasks.filter((t) => t.result && Object.keys(t.result as object).length).slice(0, 6).map((t) => (
                  <details key={t.id} className="card" style={{ padding: 12 }}>
                    <summary style={{ cursor: "pointer", fontSize: 13 }}>
                      {TASK_TYPE_FA[t.type] ?? t.type} — <StatusPill state={t.status} />
                    </summary>
                    <pre className="code-block" style={{ marginTop: 8 }}>
                      {JSON.stringify({ params: t.params, result: t.result, error: t.error }, null, 2)}
                    </pre>
                  </details>
                ))}
              </div>
            ) : tasks !== null && tasks.some((t) => t.error) ? (
              <div className="card-pad">
                {tasks.filter((t) => t.error).slice(0, 5).map((t) => (
                  <div key={t.id} className="small" style={{ color: "var(--danger)", marginBottom: 6 }}>
                    {t.type}: <span className="technical">{t.error}</span>
                  </div>
                ))}
              </div>
            ) : tasks !== null ? (
              <EmptyState title="نتیجه‌ی تشخیصی ثبت نشده" hint="پس از درخواست تسک تشخیصی، نتایج همین‌جا می‌آیند." />
            ) : <SkeletonRows rows={3} />}
          </Card>
        </div>
      )}

      {tab === "console" && (
        <RemoteConsole agentId={a.id} agentLabel={a.hostname ?? ""} />
      )}

      {tab === "manage" && (
        <div className="grid-half">
          <Card title="وضعیت ارتباط و همگام‌سازی">
            <dl className="two-col-defs">
              <dt>وضعیت</dt><dd><StatusPill state={a.status} pulse={a.status === "active"} /></dd>
              <dt>فاصله ضربان پیکربندی‌شده</dt><dd>{fmtSeconds(a.heartbeat_interval_seconds)}</dd>
              <dt>ثبت‌نام</dt><dd>{fmtDateTime(a.enrolled_at)}</dd>
              <dt>تسک در صف</dt>
              <dd>{faNum(tasks?.filter((t) => ["pending", "dispatched"].includes(t.status)).length ?? 0)}</dd>
            </dl>
            <div className="divider" />
            <div className="small muted">
              برای دریافت inventory تازه می‌توانید از تب عیب‌یابی، تسک
              «فهرست‌برداری» را صادر کنید. این صفحه با به‌روزرسانی ضربان، داده تازه را نشان می‌دهد.
            </div>
          </Card>
          <Card title="عملیات حساس" extra={<span className="badge badge-danger">نهایی</span>}>
            <div className="small" style={{ color: "var(--text-2)", lineHeight: 1.9, marginBottom: 14 }}>
              باطل‌سازی دسترسی، اعتبارنامه‌ی عامل را بی‌اثر می‌کند: ضربان، inventory و هیچ تسکی
              دیگر پذیرفته نمی‌شود. عملیات در حسابرسی با برچسب مدیر ثبت می‌شود.
            </div>
            <button className="btn danger" disabled={a.status === "revoked"} onClick={() => setRevokeOpen(true)}>
              {a.status === "revoked" ? "این عامل باطل شده است" : "باطل‌سازی دسترسی عامل"}
            </button>
          </Card>
        </div>
      )}

      <ConfirmDialog
        open={revokeOpen}
        title="باطل‌سازی دسترسی این عامل"
        message={
          <>
            اعتبارنامه‌ی <b className="technical">{a.id}</b> باطل می‌شود؛ عامل دیگر ضربان،
            inventory یا تسکی تحویل نمی‌دهد. برای بازگشت باید از فرآیند معرفی و تأیید دوباره
            عبور کند. این عملیات در حسابرسی ثبت می‌شود.
          </>
        }
        confirmLabel="باطل‌سازی دسترسی"
        danger
        busy={busyTask === "revoke"}
        onConfirm={async () => {
          setBusyTask("revoke");
          try {
            await api.post(`/api/admin/v1/agents/${agentId}/revoke`, {});
            toast.push("دسترسی عامل باطل شد.", "success");
            setRevokeOpen(false);
            setRefresh((k) => k + 1);
          } catch (e) {
            toast.push(e instanceof Error ? `باطل‌سازی ناموفق: ${e.message}` : "باطل‌سازی ناموفق", "error");
          } finally {
            setBusyTask(null);
          }
        }}
        onCancel={() => setRevokeOpen(false)}
      />
    </div>
  );
}
