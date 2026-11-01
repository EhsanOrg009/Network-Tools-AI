/**
 * Security Center: Suricata alerts with severity filter + alert-vs-evidence
 * framing (an alert is NOT proof of intrusion; allow vs drop is shown).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { AlertRow } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime, severityLabel } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, TechChip } from "../components/ui";
import { BarList, CHART_COLORS } from "../components/charts";
import { IconShield, IconAlert } from "../components/icons";

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<string>("all");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<AlertRow | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const sevQ = sev === "all" ? "" : `&severity=${sev}`;
      const d = await api.get<{ items: AlertRow[]; total: number }>(
        `/api/alerts?limit=200&group_by_flow=false${sevQ}`,
      );
      setAlerts(d.items);
      setTotal(d.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, [sev]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return alerts ?? [];
    return (alerts ?? []).filter((a) =>
      (a.src_ip ?? "").includes(needle) || (a.dest_ip ?? "").includes(needle) ||
      (a.signature ?? "").toLowerCase().includes(needle));
  }, [alerts, q]);

  const bySev = useMemo(() => {
    const m = new Map<number, number>();
    for (const a of alerts ?? []) m.set(a.severity, (m.get(a.severity) ?? 0) + 1);
    return [...m.entries()].sort((x, y) => x[0] - y[0]).map(([s, c]) => ({
      label: severityLabel(s), value: c,
      color: s <= 1 ? CHART_COLORS.danger : s === 2 ? CHART_COLORS.warn : CHART_COLORS.accent2,
    }));
  }, [alerts]);

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconShield size={20} style={{ color: "var(--danger)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>مرکز امنیت — هشدارهای Suricata</div>
            <div className="small muted">
              هر هشدار یعنی الگوی مشابه یک قانون دیده شده؛ <b>شواهد اولیه است، نه اثبات
              نفوذ</b>. ستون action فقط وضعیت بسته (allowed/drop در Suricata) را نشان می‌دهد.
            </div>
          </div>
          <div className="spacer" />
          <select className="input" style={{ width: 140 }} value={sev} onChange={(e) => { setSev(e.target.value); setRefresh((k) => k + 1); }}>
            <option value="all">همه‌ی شدت‌ها</option>
            <option value="1">بحرانی (1)</option>
            <option value="2">مهم (2)</option>
            <option value="3">متوسط (3)</option>
            <option value="4">کم (4)</option>
          </select>
          <input className="input" style={{ width: 220 }} placeholder="IP یا نام امضا…" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      <div className="grid-half" style={{ marginBottom: 14 }}>
        <Card title="تفکیک شدت — از داده‌ی همین صفحه">
          <BarList items={bySev} />
        </Card>
        <div className="card card-pad" style={{ display: "grid", placeItems: "center" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 34, fontWeight: 800 }}>{faNum(total)}</div>
            <div className="small muted">هشدار مطابق فیلتر فعلی ({sev === "all" ? "همه" : severityLabel(Number(sev))}) در پایگاه‌داده</div>
          </div>
        </div>
      </div>

      <Card pad={false} title="هشدارهای امنیتی"
        extra={<span className="badge badge-muted">{faNum(filtered.length)} نمایش‌داده‌شده از {faNum(total)}</span>}>
        {alerts === null && !error ? <SkeletonRows rows={6} />
          : error ? <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
            : filtered.length === 0 ? (
              <EmptyState title="هشداری مطابق فیلتر نیست" hint="بدون فیلتر، آخرین ۲۰۰ هشدار نمایش داده می‌شود." />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>شدت</th><th>امضا</th><th>منبع → مقصد</th><th>پروتکل</th><th>action</th><th>زمان</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 150).map((a) => (
                      <tr key={a.id} className="clickable" onClick={() => setDetail(a)}>
                        <td>
                          <span className={`badge ${a.severity <= 1 ? "badge-danger" : a.severity === 2 ? "badge-warn" : "badge-muted"}`}>
                            {severityLabel(a.severity)}
                          </span>
                        </td>
                        <td className="small" style={{ maxWidth: 280 }}>{a.signature ?? "—"}</td>
                        <td className="technical small">{a.src_ip ?? "?"}{a.src_port ? `:${a.src_port}` : ""} → {a.dest_ip ?? "?"}{a.dest_port ? `:${a.dest_port}` : ""}</td>
                        <td className="small">{[a.proto, a.app_proto].filter(Boolean).join("/") || "—"}</td>
                        <td>
                          {a.action == null ? <span className="badge badge-muted">نامشخص</span>
                            : a.action === "blocked" || a.action === "drop" ? <span className="badge badge-danger">drop</span>
                              : <span className="badge badge-warn">allowed</span>}
                        </td>
                        <td className="small muted" title={fmtDateTime(a.ts)}>{fmtAgo(a.ts)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
      </Card>

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: 10, gap: 10 }}>
              <IconAlert size={18} style={{ color: "var(--danger)" }} />
              <h3 style={{ fontSize: 15 }}>جزئیات هشدار #{detail.id}</h3>
              <div className="spacer" />
              <span className={`badge ${detail.severity <= 2 ? "badge-danger" : "badge-muted"}`}>{severityLabel(detail.severity)}</span>
            </div>
            <pre className="code-block" style={{ maxHeight: 360 }}>{JSON.stringify(detail, null, 2)}</pre>
            <div className="small muted" style={{ marginTop: 10 }}>
              این رکورد شواهد خام Suricata است. برای تثبیت نظر، از «بررسی‌های هوشمند» یک
              تحقیق روی IP منبع اجرا کنید — و در افزودن اقدام، محافظه‌کار باشید.
            </div>
            <div className="row" style={{ marginTop: 14 }}>
              <TechChip>{`alert_id=${detail.id}`}</TechChip>
              <div className="spacer" />
              <button className="btn ghost" onClick={() => setDetail(null)}>بستن</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
