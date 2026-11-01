import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type { Overview, EnrollmentRequest } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime } from "../lib/format";
import { StatCard, Card, EmptyState, ErrorState, Skeleton, StatusPill } from "../components/ui";
import { BarList, CHART_COLORS, Donut, TrendChart } from "../components/charts";
import { IconAgents, IconGauge, IconShield, IconWifi, IconInbox, IconTerminal, IconHeartbeat } from "../components/icons";
import { severityLabel } from "../lib/format";
import { CommandCenter } from "../components/CommandCenter";

export default function OverviewPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setError(null);
      const d = await api.get<Overview>("/api/dashboard/v1/overview");
      setData(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  if (loading && !data) {
    return (
      <div>
        <div className="stats-grid">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="card stat-card" style={{ minHeight: 98 }}>
              <Skeleton width={80} height={26} />
              <Skeleton width={110} height={12} />
            </div>
          ))}
        </div>
        <div className="grid-2 section-gap">
          <div className="card card-pad"><Skeleton height={190} /></div>
          <div className="card card-pad"><Skeleton height={190} /></div>
        </div>
      </div>
    );
  }
  if (error && !data) return <div className="card"><ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} /></div>;
  if (!data) return null;

  const { agents } = data;
  const sevColors: Record<number, string> = { 1: CHART_COLORS.danger, 2: CHART_COLORS.warn, 3: CHART_COLORS.accent2, 4: CHART_COLORS.sev4 };
  const health =
    agents.active > 0 && agents.revoked === 0
      ? "پایدار"
      : agents.active > 0
        ? "نیازمند توجه"
        : agents.pending_approval > 0 ? "در انتظار تأیید" : "بدون عامل فعال";

  return (
    <div>
      <div className="stats-grid">
        <StatCard label="عامل‌های فعال (آنلاین)" value={faNum(agents.active)}
          hint={`از مجموع ${faNum(agents.total)} عامل ثبت‌شده${agents.revoked ? ` — ${faNum(agents.revoked)} باطل‌شده` : ""}`}
          icon={<IconAgents size={19} />} color={CHART_COLORS.ok} />
        <StatCard label="عامل بدون ضربان (Stale)" value={faNum(agents.stale)}
          hint="اخیراً ضربانی ثبت نشده؛ خاموشی قطعی نیست"
          icon={<IconHeartbeat size={19} />} color={CHART_COLORS.warn} />
        <StatCard label="درخواست‌های تأییدنشده" value={faNum(agents.pending_approval)}
          hint={agents.pending_approval > 0 ? "نیازمند تصمیم مدیر" : "صف خالی است"}
          icon={<IconInbox size={19} />}
          color={agents.pending_approval > 0 ? CHART_COLORS.danger : CHART_COLORS.muted} />
        <StatCard label="میزبان‌های شناسایی‌شده" value={faNum(data.hosts)}
          hint={`${faNum(data.alerts.last_24h)} هشدار در ۲۴ ساعت اخیر`}
          icon={<IconWifi size={19} />} color={CHART_COLORS.accent2} />
        <StatCard label="هشدارهای Suricata" value={faNum(data.alerts.total)}
          hint={`مجموع ثبت‌شده — ${faNum(data.events.last_24h)} رویداد در ۲۴ ساعت`}
          icon={<IconShield size={19} />} color={CHART_COLORS.danger} />
        <StatCard label="نشست‌های کنسول فعال" value={faNum(data.console_sessions_active)}
          hint={`${faNum(data.tasks.pending ?? 0)} تسک در صف`}
          icon={<IconTerminal size={19} />} color={CHART_COLORS.accent} />
      </div>

      <div className="section-gap" style={{ marginBottom: 14 }}>
        <CommandCenter />
      </div>

      <div className="grid-2">
        <Card
          title={<><IconGauge size={16} /> روند ۷ روزه‌ی رخدادها، هشدارها و عملیات مدیر</>}
          extra={<span className="small muted">منبع: پایگاه‌داده‌ی هسته</span>}
        >
          <TrendChart
            data={data.trend_7d}
            series={[
              { key: "events", label: "رویداد خام", color: CHART_COLORS.accent2 },
              { key: "alerts", label: "هشدار امنیتی", color: CHART_COLORS.danger },
              { key: "audit", label: "عملیات مدیر", color: CHART_COLORS.ok },
            ]}
          />
        </Card>
        <Card title="وضعیت عامل‌ها" extra={
          <span className={`badge ${health === "پایدار" ? "badge-ok" : health === "بدون عامل فعال" ? "badge-muted" : "badge-warn"}`}>{health}</span>
        }>
          <Donut
            centerValue={faNum(agents.total - agents.revoked)}
            centerLabel="عامل بدون احتساب باطل‌شده"
            slices={[
              { label: "آنلاین", value: agents.active, color: CHART_COLORS.ok },
              { label: "بدون ضربان", value: agents.stale, color: CHART_COLORS.warn },
              { label: "باطل‌شده", value: agents.revoked, color: CHART_COLORS.muted },
              { label: "در انتظار تأیید", value: agents.pending_approval, color: CHART_COLORS.accent },
            ]}
          />
        </Card>
      </div>

      <div className="grid-half section-gap">
        <Card title="تفکیک شدت هشدارهای امنیتی">
          <BarList
            color={CHART_COLORS.danger}
            items={data.alerts.by_severity.map((s) => ({
              label: `${severityLabel(s.severity)} (severity=${s.severity})`,
              value: s.count, color: sevColors[s.severity] ?? CHART_COLORS.muted,
            }))}
          />
          <div className="divider" />
          <div className="small muted">
            هشدار یعنی الگویی مشابه قانون Suricata دیده شده؛ اثبات قطعی نفوذ نیست.
          </div>
        </Card>

        <Card title="آخرین عملیات ثبت‌شده (حسابرسی)" extra={
          <Link to="/dashboard/settings" className="small">/rss</Link>
        }>
          {data.recent_audit.length === 0 ? (
            <EmptyState title="فعالیتی ثبت نشده" hint="پس از کنش‌های مدیر و عامل‌ها اینجا دیده می‌شود." />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {data.recent_audit.slice(0, 8).map((a, i) => (
                <div key={i} className="row" style={{ gap: 10, fontSize: 12.5 }}>
                  <span className="code-chip" style={{ fontSize: 11 }}>{a.action}</span>
                  <span className="muted small">{a.actor}</span>
                  <span className="small muted technical">{a.target ?? ""}</span>
                  <span className="spacer" />
                  <span className="small muted">{fmtAgo(a.at)}</span>
                </div>
              ))}
            </div>
          )}
          <div className="small muted" style={{ marginTop: 10 }}>
            آخرین به‌روزرسانی آمار: {fmtDateTime(data.generated_at)}
          </div>
        </Card>
      </div>

      {agents.pending_requests?.length > 0 && (
        <Card
          className="section-gap"
          pad
          title={<><IconInbox size={16} /> درخواست‌های ثبت‌نام در انتظار تصمیم شما</>}
          extra={<Link className="btn sm" to="/dashboard/pending">همه‌ی درخواست‌ها</Link>}
        >
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Hostname (اعلامی)</th><th>سیستم‌عامل</th><th>IPهای اعلامی</th><th>زمان درخواست</th><th></th></tr>
              </thead>
              <tbody>
                {agents.pending_requests.slice(0, 5).map((r: EnrollmentRequest) => (
                  <tr key={r.id}>
                    <td className="technical">{r.hostname ?? "—"}</td>
                    <td>{String((r.platform as { os_family?: string })?.os_family ?? "—")}</td>
                    <td className="technical small">{(r.claimed_ips ?? []).join(" ، ") || "—"}</td>
                    <td>{fmtDateTime(r.requested_at)}</td>
                    <td><StatusPill state={r.status} pulse /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
