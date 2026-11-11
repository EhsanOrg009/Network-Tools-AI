import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import type { AgentSummary } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime } from "../lib/format";
import { Card, StatCard, EmptyState, ErrorState, SkeletonRows, StatusPill, TechChip, ConfirmDialog } from "../components/ui";
import { IconSearch, IconAgents, IconHeartbeat, IconOff } from "../components/icons";
import { useToast } from "../components/toast";

type SortKey = "status" | "hostname" | "platform" | "enrolled_at" | "last_heartbeat_at";

const OS_FILTERS = ["همه", "Windows", "Linux", "macOS", "FreeBSD", "Darwin"];

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [osFilter, setOsFilter] = useState("همه");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "status", dir: 1 });
  const [revokeTarget, setRevokeTarget] = useState<AgentSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshKey, setRefresh] = useState(0);
  const toast = useToast();
  const navigate = useNavigate();

  const load = useCallback(async () => {
    try {
      setError(null);
      const d = await api.get<{ items: AgentSummary[] }>("/api/admin/v1/agents?include_revoked=true&limit=500");
      setAgents(d.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const filtered = useMemo(() => {
    let items = [...(agents ?? [])];
    const needle = q.trim().toLowerCase();
    if (needle) {
      items = items.filter((a) =>
        (a.hostname ?? "").toLowerCase().includes(needle) ||
        a.id.toLowerCase().includes(needle) ||
        (a.claimed_ips ?? []).some((ip) => ip.toLowerCase().includes(needle)),
      );
    }
    if (stateFilter !== "all") items = items.filter((a) => a.status === stateFilter);
    if (osFilter !== "همه") {
      items = items.filter((a) => (a.platform ?? "").toLowerCase().includes(osFilter.toLowerCase()));
    }
    const rank: Record<string, number> = { active: 0, stale: 1, revoked: 2 };
    items.sort((a, b) => {
      let r = 0;
      if (sort.key === "status") r = (rank[a.status] ?? 3) - (rank[b.status] ?? 3);
      else if (sort.key === "hostname" || sort.key === "platform") r = (a[sort.key] ?? "").localeCompare(b[sort.key] ?? "");
      else r = new Date(a[sort.key] ?? 0).getTime() - new Date(b[sort.key] ?? 0).getTime();
      return r * sort.dir;
    });
    return items;
  }, [agents, q, stateFilter, osFilter, sort]);

  async function doRevoke() {
    if (!revokeTarget) return;
    setBusy(true);
    try {
      await api.post(`/api/admin/v1/agents/${revokeTarget.id}/revoke`, {});
      toast.push(`دسترسی «${revokeTarget.hostname ?? revokeTarget.id}» باطل شد.`, "success");
      setRevokeTarget(null);
      setRefresh((k) => k + 1);
    } catch (e) {
      toast.push(e instanceof Error ? `باطل‌سازی ناموفق: ${e.message}` : "باطل‌سازی ناموفق", "error");
    } finally {
      setBusy(false);
    }
  }

  function toggleSort(key: SortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
  }

  return (
    <div>
      {agents && <div className="stats-grid">
        <StatCard label="عامل‌های آنلاین" value={faNum(agents.filter((a) => a.status === "active").length)} icon={<IconAgents size={18} />} color="var(--ok)" hint="با ضربان تازه در هسته" />
        <StatCard label="بدون ضربان تازه" value={faNum(agents.filter((a) => a.status === "stale").length)} icon={<IconHeartbeat size={18} />} color="var(--warn)" hint="نیازمند بررسی ارتباط دستگاه" />
        <StatCard label="دسترسی باطل‌شده" value={faNum(agents.filter((a) => a.status === "revoked").length)} icon={<IconOff size={18} />} color="var(--muted)" hint="تاریخچه و شناسه محفوظ است" />
      </div>}
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap">
          <div style={{ width: "min(300px, 100%)" }}>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", insetBlockStart: 8, insetInlineEnd: 10, color: "var(--text-3)" }}>
                <IconSearch size={16} />
              </span>
              <input
                className="input"
                style={{ paddingInlineEnd: 34 }}
                placeholder="جست‌وجوی نام، IP یا شناسه…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
          </div>
          <select className="input" style={{ width: 160 }} value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="all">همه‌ی وضعیت‌ها</option>
            <option value="active">آنلاین</option>
            <option value="stale">بدون ضربان</option>
            <option value="revoked">باطل‌شده</option>
          </select>
          <select className="input" style={{ width: 150 }} value={osFilter} onChange={(e) => setOsFilter(e.target.value)}>
            {OS_FILTERS.map((o) => <option key={o} value={o}>{o === "همه" ? "همه‌ی سیستم‌عامل‌ها" : o}</option>)}
          </select>
          <div className="spacer" />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      <Card pad={false}>
        {agents === null && !error ? (
          <SkeletonRows rows={5} />
        ) : error ? (
          <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
        ) : (filtered ?? []).length === 0 ? (
          <EmptyState
            title="عاملی مطابق جست‌وجو نیست"
            hint="عامل‌های جدید پس از تأیید از بخش «در انتظار تأیید» اینجا می‌آیند."
          />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th aria-sort={sort.key === "hostname" ? sort.dir === 1 ? "ascending" : "descending" : "none"}><button onClick={() => toggleSort("hostname")}>نام میزبان ↕</button></th>
                  <th>IPهای اعلامی</th>
                  <th aria-sort={sort.key === "platform" ? sort.dir === 1 ? "ascending" : "descending" : "none"}><button onClick={() => toggleSort("platform")}>سیستم‌عامل ↕</button></th>
                  <th>نسخه عامل</th>
                  <th><button onClick={() => toggleSort("status")}>وضعیت ↕</button></th>
                  <th><button onClick={() => toggleSort("last_heartbeat_at")}>آخرین ضربان ↕</button></th>
                  <th><button onClick={() => toggleSort("enrolled_at")}>ثبت‌نام ↕</button></th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => navigate(`/dashboard/agents/${a.id}`)}>
                    <td>
                      <button className="btn ghost sm technical" onClick={() => navigate(`/dashboard/agents/${a.id}`)}>{a.hostname ?? "—"}</button>
                      <TechChip>{a.id}</TechChip>
                    </td>
                    <td className="technical small">{(a.claimed_ips ?? [])[0] ?? "—"}</td>
                    <td>{a.platform ?? "—"}</td>
                    <td className="technical small">{a.agent_version ?? "—"}</td>
                    <td><StatusPill state={a.status} pulse={a.status === "active"} /></td>
                    <td title={fmtDateTime(a.last_heartbeat_at)}>{fmtAgo(a.last_heartbeat_at)}</td>
                    <td title={fmtDateTime(a.enrolled_at)}>{fmtAgo(a.enrolled_at)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.status !== "revoked" && (
                        <button className="btn danger sm" onClick={() => setRevokeTarget(a)}>باطل‌سازی</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="row section-gap">
        <span className="small muted">{faNum(filtered.length)} عامل</span>
      </div>

      <ConfirmDialog
        open={!!revokeTarget}
        title="باطل‌سازی دسترسی عامل"
        danger
        busy={busy}
        message={
          <>
            اعتبارنامه‌ی عامل <b className="technical">{revokeTarget?.hostname ?? revokeTarget?.id}</b> باطل می‌شود؛
            عامل دیگر نمی‌تواند ضربان بفرستد یا تسک اجرا کند. برای ثبت‌نام دوباره، همان دستگاه باید از
            مراحل معرفی و تأیید مدیر عبور کند. این عملیات در حسابرسی ثبت می‌شود.
          </>
        }
        confirmLabel="باطل‌سازی دسترسی"
        onConfirm={doRevoke}
        onCancel={() => setRevokeTarget(null)}
      />
    </div>
  );
}
