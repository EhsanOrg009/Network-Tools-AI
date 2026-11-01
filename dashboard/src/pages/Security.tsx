/**
 * Security Center: Suricata alerts + per-alert AI analysis (background queue).
 * Alert-vs-evidence framing is kept: an alert is NOT proof of intrusion, and
 * the AI column is clearly labeled as the model's interpretation.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { AlertRow } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime, severityLabel } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, TechChip } from "../components/ui";
import { BarList, CHART_COLORS } from "../components/charts";
import { IconShield, IconAlert } from "../components/icons";

export interface AlertAnalysisRow {
  alert_id: number;
  status: "PENDING" | "PROCESSING" | "COMPLETED" | "FAILED";
  summary: string | null;
  importance: "low" | "medium" | "high" | null;
  evidence?: string[] | null;
  anomaly_likelihood: string | null;
  confidence: string | null;
  recommendation: string | null;
  model: string | null;
  prompt_version: string | null;
  error: string | null;
  attempts: number;
  analyzed_at: string | null;
}

const importanceBadge: Record<string, string> = {
  low: "badge-muted", medium: "badge-warn", high: "badge-danger",
};
const likelihoodFa: Record<string, string> = {
  low: "کم", medium: "متوسط", high: "زیاد", unknown: "نامشخص",
};

function AnalysisCell({ analysis, onOpen }: { analysis?: AlertAnalysisRow; onOpen: () => void }) {
  if (!analysis) return <span className="small muted">در صف…</span>;
  if (analysis.status === "COMPLETED") {
    return (
      <button className="btn ghost analysis-cell" onClick={onOpen} title="نمایش تحلیل کامل">
        <span className={`badge ${importanceBadge[analysis.importance ?? "low"] ?? "badge-muted"}`}>
          {analysis.importance === "high" ? "مهم" : analysis.importance === "medium" ? "متوسط" : "کم"}
        </span>
        <span className="small" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {analysis.summary ?? "—"}
        </span>
      </button>
    );
  }
  if (analysis.status === "PROCESSING") {
    return <span className="badge badge-accent"><span className="dot pulse" />در حال تحلیل…</span>;
  }
  if (analysis.status === "PENDING") {
    return <span className="badge badge-muted">در صف</span>;
  }
  return (
    <button className="btn ghost analysis-cell" onClick={onOpen}>
      <span className="badge badge-danger">خطای تحلیل</span>
      <span className="small muted">جزئیات</span>
    </button>
  );
}

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [analyses, setAnalyses] = useState<Map<number, AlertAnalysisRow>>(new Map());
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<string>("all");
  const [aiFilter, setAiFilter] = useState<string>("all");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<AlertRow | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const sevQ = sev === "all" ? "" : `&severity=${sev}`;
      const [d, ai] = await Promise.all([
        api.get<{ items: AlertRow[]; total: number }>(
          `/api/alerts?limit=200&group_by_flow=false${sevQ}`,
        ),
        // analyses live behind the admin API; alerts must still render if it fails
        api.get<{ items: AlertAnalysisRow[] }>("/api/admin/v1/ai-analyses?limit=500")
          .catch(() => ({ items: [] as AlertAnalysisRow[] })),
      ]);
      setAlerts(d.items);
      setTotal(d.total);
      const map = new Map<number, AlertAnalysisRow>();
      for (const row of (ai.items ?? []) as AlertAnalysisRow[]) {
        if (typeof row?.alert_id === "number") map.set(row.alert_id, row);
      }
      setAnalyses(map);
    } catch (e) {
      setError(
        e instanceof ApiError ? e.detail
        : e instanceof Error ? e.message
        : "خطای ناشناخته",
      );
    }
  }, [sev]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const reanalyze = useCallback(async (alertId: number) => {
    setBusy(alertId);
    try {
      await api.post(`/api/admin/v1/ai-analyses/${alertId}/reanalyze`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : "تحلیل مجدد ناموفق بود.");
    } finally {
      setBusy(null);
    }
  }, [load]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (alerts ?? []).filter((a) => {
      if (needle
        && !(a.src_ip ?? "").includes(needle)
        && !(a.dest_ip ?? "").includes(needle)
        && !(a.signature ?? "").toLowerCase().includes(needle)) return false;
      if (aiFilter === "all") return true;
      const st = analyses.get(a.id)?.status;
      if (aiFilter === "none") return !st;
      return st === aiFilter;
    });
  }, [alerts, q, aiFilter, analyses]);

  const bySev = useMemo(() => {
    const m = new Map<number, number>();
    for (const a of alerts ?? []) m.set(a.severity, (m.get(a.severity) ?? 0) + 1);
    return [...m.entries()].sort((x, y) => x[0] - y[0]).map(([s, c]) => ({
      label: severityLabel(s), value: c,
      color: s <= 1 ? CHART_COLORS.danger : s === 2 ? CHART_COLORS.warn : CHART_COLORS.accent2,
    }));
  }, [alerts]);

  const detailAnalysis = detail ? analyses.get(detail.id) : undefined;

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconShield size={20} style={{ color: "var(--danger)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>مرکز امنیت — هشدارهای Suricata + تحلیل هوش مصنوعی</div>
            <div className="small muted">
              هر هشدار یعنی الگوی مشابه یک قانون دیده شده؛ <b>شواهد اولیه است، نه اثبات نفوذ</b>.
              ستون «تحلیل هوش مصنوعی» برداشت مدل است (پس‌زمینه‌ای و تدریجی)، نه واقعیت قطعی.
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
          <select className="input" style={{ width: 160 }} value={aiFilter} onChange={(e) => setAiFilter(e.target.value)}>
            <option value="all">تحلیل: همه</option>
            <option value="COMPLETED">تحلیل‌شده</option>
            <option value="PENDING">در صف تحلیل</option>
            <option value="PROCESSING">در حال تحلیل</option>
            <option value="FAILED">خطای تحلیل</option>
            <option value="none">بدون تحلیل</option>
          </select>
          <input className="input" style={{ width: 200 }} placeholder="IP یا نام امضا…" value={q} onChange={(e) => setQ(e.target.value)} />
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
            <div className="small muted" style={{ marginTop: 6 }}>
              تحلیل‌شده: {faNum([...analyses.values()].filter((a) => a.status === "COMPLETED").length)} ·
              در صف: {faNum([...analyses.values()].filter((a) => a.status !== "COMPLETED").length)}
            </div>
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
                      <th>شدت</th><th>امضا</th><th>منبع → مقصد</th><th>پروتکل</th><th>action</th>
                      <th>تحلیل هوش مصنوعی</th><th>زمان</th>
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
                        <td className="small" style={{ maxWidth: 240 }}>{a.signature ?? "—"}</td>
                        <td className="technical small">{a.src_ip ?? "?"}{a.src_port ? `:${a.src_port}` : ""} → {a.dest_ip ?? "?"}{a.dest_port ? `:${a.dest_port}` : ""}</td>
                        <td className="small">{[a.proto, a.app_proto].filter(Boolean).join("/") || "—"}</td>
                        <td>
                          {a.action == null ? <span className="badge badge-muted">نامشخص</span>
                            : a.action === "blocked" || a.action === "drop" ? <span className="badge badge-danger">drop</span>
                              : <span className="badge badge-warn">allowed</span>}
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <AnalysisCell analysis={analyses.get(a.id)} onOpen={() => setDetail(a)} />
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
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 720 }}>
            <div className="row" style={{ marginBottom: 10, gap: 10 }}>
              <IconAlert size={18} style={{ color: "var(--danger)" }} />
              <h3 style={{ fontSize: 15 }}>هشدار #{detail.id} — شواهد و تحلیل</h3>
              <div className="spacer" />
              <span className={`badge ${detail.severity <= 2 ? "badge-danger" : "badge-muted"}`}>{severityLabel(detail.severity)}</span>
            </div>

            {detailAnalysis && (
              <div className="card card-pad" style={{ background: "var(--bg-card-2)", marginBottom: 12 }}>
                <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                  <b>تحلیل هوش مصنوعی</b>
                  <span className={`badge ${detailAnalysis.status === "COMPLETED" ? "badge-ok" : detailAnalysis.status === "FAILED" ? "badge-danger" : "badge-muted"}`}>
                    {detailAnalysis.status}
                  </span>
                  {detailAnalysis.model && <span className="small muted">{detailAnalysis.model}</span>}
                  <div className="spacer" />
                  <button
                    className="btn"
                    disabled={busy === detail.id}
                    onClick={() => { void reanalyze(detail.id); }}
                  >
                    {busy === detail.id ? "…" : "⟳ تحلیل مجدد"}
                  </button>
                </div>
                {detailAnalysis.status === "COMPLETED" ? (
                  <>
                    <p style={{ margin: "4px 0" }}>{detailAnalysis.summary}</p>
                    {detailAnalysis.evidence && detailAnalysis.evidence.length > 0 && (
                      <div className="small" style={{ margin: "8px 0" }}>
                        <b>شواهد در همین رکورد:</b>
                        <ul style={{ margin: "4px 16px 0 0" }}>
                          {detailAnalysis.evidence.map((ev, i) => <li key={i} className="small">{ev}</li>)}
                        </ul>
                      </div>
                    )}
                    <div className="small muted" style={{ marginTop: 8 }}>
                      احتمال غیرعادی بودن: {likelihoodFa[detailAnalysis.anomaly_likelihood ?? "unknown"]} ·
                      اطمینان مدل: {likelihoodFa[detailAnalysis.confidence ?? "unknown"]}
                    </div>
                    {detailAnalysis.recommendation && (
                      <div className="small" style={{ marginTop: 6 }}>
                        <b>پیشنهاد اقدام:</b> {detailAnalysis.recommendation}
                      </div>
                    )}
                    <div className="small muted" style={{ marginTop: 8, borderTop: "1px solid var(--border)", paddingTop: 8 }}>
                      این متن برداشت مدل از شواهد است — نه واقعیت قطعی. تصمیم نهایی با مدیر شبکه است.
                    </div>
                  </>
                ) : detailAnalysis.status === "FAILED" ? (
                  <div className="small" style={{ color: "var(--danger)" }}>
                    خطا: {detailAnalysis.error ?? "نامشخص"} (تلاش {faNum(detailAnalysis.attempts)})
                  </div>
                ) : (
                  <div className="small muted">تحلیل در صف/در حال اجراست؛ به‌زودی این‌جا نمایش داده می‌شود.</div>
                )}
              </div>
            )}

            <div className="small muted" style={{ marginBottom: 4 }}>شواهد خام Suricata:</div>
            <pre className="code-block" style={{ maxHeight: 280 }}>{JSON.stringify(detail, null, 2)}</pre>
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
