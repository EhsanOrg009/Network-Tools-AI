/**
 * Security Center: Suricata alerts + per-alert AI analysis (background queue).
 * Alert-vs-evidence framing is kept: an alert is NOT proof of intrusion, and
 * the AI column is clearly labeled as the model's interpretation.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { AlertRow } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime, severityLabel } from "../lib/format";
import { Card, Dialog, EmptyState, ErrorState, MiniSpinner, SkeletonRows, TechChip } from "../components/ui";
import { BarList, CHART_COLORS } from "../components/charts";
import { IconShield, IconAlert } from "../components/icons";

export interface AlertAnalysisRow {
  alert_id: number;
  job_id?: string;
  origin?: string;
  provider_failures?: number;
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

interface SecurityAIStatus {
  auto_enabled: boolean;
  counts: Record<"PENDING" | "PROCESSING" | "COMPLETED" | "FAILED", number>;
  last_processed_at: string | null;
  last_error: string | null;
  model: string;
  connection: { ok: boolean; detail: string };
  worker_enabled: boolean;
  backlog_policy: "future_only" | "recent_unprocessed";
  backlog_limit: number;
  paused_automatic: number;
  capacity: number;
  intake_capacity: number;
  intake_count: number;
  unprocessed: number;
}

const importanceBadge: Record<string, string> = {
  low: "badge-muted", medium: "badge-warn", high: "badge-danger",
};
const likelihoodFa: Record<string, string> = {
  low: "کم", medium: "متوسط", high: "زیاد", unknown: "نامشخص",
};
const analysisStatusFa = { PENDING: "در صف", PROCESSING: "در حال پردازش", COMPLETED: "تکمیل‌شده", FAILED: "ناموفق" };

function AnalysisCell({ analysis, onOpen, unavailable, paused }: { analysis?: AlertAnalysisRow; onOpen: () => void; unavailable: boolean; paused: boolean }) {
  if (unavailable) return <span className="small muted">وضعیت تحلیل نامشخص</span>;
  if (!analysis) return <span className="small muted">تحلیل نشده</span>;
  if (analysis.status === "COMPLETED") {
    return (
      <button className="btn ghost analysis-cell" onClick={onOpen} title="نمایش تحلیل کامل">
        <span className="badge badge-ok">تکمیل‌شده</span>
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
    if (paused) return <span className="badge badge-warn">متوقف — خودکار خاموش</span>;
    return <span className="badge badge-muted" title={analysis.error ?? undefined}>{analysis.error ? "در صف — خطای مدل" : "در صف"}</span>;
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
  const [search, setSearch] = useState("");
  const [severityCounts, setSeverityCounts] = useState<{ severity: number; count: number }[]>([]);
  const [detail, setDetail] = useState<AlertRow | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [refreshKey, setRefresh] = useState(0);
  const [aiStatus, setAIStatus] = useState<SecurityAIStatus | null>(null);
  const [aiError, setAIError] = useState<string | null>(null);
  const [autoBusy, setAutoBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [backlogPolicy, setBacklogPolicy] = useState<"future_only" | "recent_unprocessed">("future_only");
  const [backlogLimit, setBacklogLimit] = useState(50);
  const initializedPolicy = useRef(false);
  const sequence = useRef(0);
  const actionInFlight = useRef(false);
  const pageSize = 50;
  const detailId = detail?.id;

  useEffect(() => {
    const timer = setTimeout(() => { setSearch(q.trim()); setPage(0); }, 300);
    return () => clearTimeout(timer);
  }, [q]);

  const load = useCallback(async (signal?: AbortSignal) => {
    const version = ++sequence.current;
    const current = () => !signal?.aborted && version === sequence.current;
    try {
      setError(null);
      const sevQ = sev === "all" ? "" : `&severity=${sev}`;
      const searchQ = search ? `&q=${encodeURIComponent(search)}` : "";
      const analysisQ = aiFilter === "all" ? "" : `&analysis_status=${aiFilter}`;
      const [d, status] = await Promise.all([
        api.get<{ items: AlertRow[]; total: number; severity_counts: { severity: number; count: number }[] }>(
          `/api/alerts?limit=${pageSize}&offset=${page * pageSize}&group_by_flow=false&include_summary=true${sevQ}${searchQ}${analysisQ}`, { signal },
        ),
        api.get<SecurityAIStatus>("/api/admin/v1/security-ai", { signal }).catch(() => null),
      ]);
      if (!current()) return;
      setAlerts(d.items);
      setTotal(d.total);
      setSeverityCounts(d.severity_counts);
      setAIStatus(status);
      if (status && !initializedPolicy.current) {
        setBacklogPolicy(status.backlog_policy ?? "future_only");
        setBacklogLimit(status.backlog_limit ?? 50);
        initializedPolicy.current = true;
      }
      let ai: { items: AlertAnalysisRow[] };
      try {
        // Keep the open event observable even when a status filter or live
        // update removes it from this page after an analysis starts.
        const ids = new Set(d.items.map((a) => a.id));
        if (detailId !== undefined) ids.add(detailId);
        ai = ids.size ? await api.get<{ items: AlertAnalysisRow[] }>(
          `/api/admin/v1/ai-analyses?alert_ids=${[...ids].join(",")}`, { signal },
        ) : { items: [] };
        if (!current()) return;
        setAIError(status ? null : "دریافت وضعیت مدل و تنظیم خودکار ناموفق بود.");
      } catch (e) {
        if (!current()) return;
        setAIError(e instanceof ApiError ? e.detail : "دریافت وضعیت تحلیل ناموفق بود.");
        return;
      }
      const map = new Map<number, AlertAnalysisRow>();
      for (const row of (ai.items ?? []) as AlertAnalysisRow[]) {
        if (typeof row?.alert_id === "number") map.set(row.alert_id, row);
      }
      setAnalyses(map);
    } catch (e) {
      if (!current()) return;
      setError(
        e instanceof ApiError ? e.detail
        : e instanceof Error ? e.message
        : "خطای ناشناخته",
      );
    }
  }, [sev, page, search, aiFilter, detailId]);

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      await load(controller.signal);
      if (!stopped) timer = setTimeout(refresh, 5000);
    };
    void refresh();
    return () => { stopped = true; controller.abort(); clearTimeout(timer); };
  }, [load, refreshKey]);

  const toggleAuto = async () => {
    if (!aiStatus || autoBusy) return;
    setAutoBusy(true);
    setActionError(null);
    try {
      await api.put("/api/admin/v1/security-ai/automatic", { enabled: !aiStatus.auto_enabled,
        backlog_policy: backlogPolicy, backlog_limit: backlogLimit });
      await load();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.detail : "تغییر حالت خودکار ناموفق بود.");
    } finally { setAutoBusy(false); }
  };

  const analyze = async (alertId: number) => {
    if (actionInFlight.current) return;
    actionInFlight.current = true;
    setBusy(alertId);
    setActionError(null);
    try {
      await api.post(`/api/admin/v1/ai-analyses/${alertId}/analyze`);
      await load();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.detail : "ثبت تحلیل ناموفق بود.");
    } finally { setBusy(null); actionInFlight.current = false; }
  };

  const reanalyze = useCallback(async (alertId: number) => {
    if (actionInFlight.current) return;
    actionInFlight.current = true;
    setBusy(alertId);
    setActionError(null);
    try {
      await api.post(`/api/admin/v1/ai-analyses/${alertId}/reanalyze`);
      await load();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.detail : "تحلیل مجدد ناموفق بود.");
    } finally {
      setBusy(null);
      actionInFlight.current = false;
    }
  }, [load]);

  const filtered = alerts ?? [];

  const bySev = useMemo(() => {
    return severityCounts.map(({ severity, count }) => ({
      label: severityLabel(severity), value: count,
      color: severity <= 1 ? CHART_COLORS.danger : severity === 2 ? CHART_COLORS.warn : CHART_COLORS.accent2,
    }));
  }, [severityCounts]);

  const detailAnalysis = detail ? analyses.get(detail.id) : undefined;
  const detailPaused = detailAnalysis?.status === "PENDING" && detailAnalysis.origin !== "manual" && aiStatus?.auto_enabled === false;
  const modeError = !!aiError || (aiStatus?.auto_enabled && (!aiStatus.connection.ok || !aiStatus.worker_enabled));

  return (
    <div>
      <section className={`card security-control${modeError ? " has-error" : ""}`} aria-label="کنترل تحلیل امنیت">
        <div className="security-mode">
          <span className="security-mode-icon"><IconShield size={23} /></span>
          <div className="security-mode-copy"><h2>تحلیل خودکار هوش مصنوعی</h2>
            <p>{aiStatus?.auto_enabled ? "هشدارهای تازه با ظرفیت کنترل‌شده وارد صف تحلیل می‌شوند." : "دریافت و ذخیرهٔ هشدارها ادامه دارد؛ تحلیل تکی با انتخاب شما انجام می‌شود."}</p>
          </div>
          {modeError && <span className="badge badge-danger" role="status">تحلیل نیازمند توجه</span>}
          <button className="btn auto-switch" role="switch" aria-label="تحلیل خودکار هوش مصنوعی"
            aria-checked={aiStatus?.auto_enabled ?? false} disabled={autoBusy || !aiStatus || backlogLimit < 1 || backlogLimit > 200}
            onClick={() => { void toggleAuto(); }}>
            {autoBusy && <MiniSpinner />}
            {aiStatus ? (aiStatus.auto_enabled ? "روشن — ON" : "خاموش — OFF") : "دریافت وضعیت…"}
          </button>
        </div>
        {aiStatus && <div className="security-queue">
          {([{ label: "در صف تحلیل", value: aiStatus.counts.PENDING }, { label: "در حال پردازش", value: aiStatus.counts.PROCESSING },
            { label: "تحلیل تکمیل‌شده", value: aiStatus.counts.COMPLETED }, { label: "تحلیل ناموفق", value: aiStatus.counts.FAILED }]).map((item) =>
              <div className="security-queue-item" key={item.label}><span>{item.label}</span><b>{faNum(item.value)}</b></div>)}
        </div>}
        <div className="security-control-body">
          <div className="row wrap small" style={{ marginTop: 16 }}>
            <label htmlFor="backlog-policy">هنگام روشن‌کردن:</label>
            <select id="backlog-policy" className="input" style={{ width: 260 }} disabled={autoBusy || aiStatus?.auto_enabled}
              value={backlogPolicy} onChange={(e) => setBacklogPolicy(e.target.value as typeof backlogPolicy)}>
              <option value="future_only">فقط هشدارهای آینده</option>
              <option value="recent_unprocessed">آخرین هشدارهای تحلیل‌نشده</option>
            </select>
            {backlogPolicy === "recent_unprocessed" && <label className="row">حداکثر
              <input aria-label="تعداد هشدارهای قدیمی" type="number" className="input" style={{ width: 90 }} min={1} max={200}
                disabled={autoBusy || aiStatus?.auto_enabled} value={backlogLimit} onChange={(e) => setBacklogLimit(Number(e.target.value))} /> هشدار (۱ تا ۲۰۰)
            </label>}
          </div>
          <p className="small muted" style={{ marginTop: 12 }}>خاموش‌کردن، کارهای خودکارِ منتظر را متوقف می‌کند. تحلیل‌های شروع‌شده تکمیل می‌شوند و تحلیل دستی همیشه مستقل است.</p>
          {aiStatus && <>
            <div className="row wrap small" style={{ marginTop: 14, gap: 18 }}>
              <span className={aiStatus.connection.ok ? "badge badge-ok" : "badge badge-danger"}>{aiStatus.connection.ok ? "مدل متصل" : "مدل در دسترس نیست"}</span>
              <bdi className="technical muted">{aiStatus.model}</bdi>
              <span className="muted">خودکار متوقف: {faNum(aiStatus.paused_automatic ?? 0)}</span>
              <span className="muted">بدون درخواست: {faNum(aiStatus.unprocessed ?? 0)}</span>
              <span className="muted">ظرفیت پردازش: {faNum(aiStatus.capacity ?? 200)}</span>
            </div>
            {!aiStatus.connection.ok && <p className="small" style={{ marginTop: 8, color: "var(--danger)" }}>وضعیت اتصال مدل: <bdi>{aiStatus.connection.detail}</bdi></p>}
            {!aiStatus.worker_enabled && <p className="small" style={{ marginTop: 8, color: "var(--warn)" }}>worker تحلیل در تنظیمات سرور غیرفعال است؛ درخواست‌ها محفوظ می‌مانند.</p>}
            <details className="small muted" style={{ marginTop: 12 }}><summary>آخرین پردازش و خطای مدل</summary>
              <p>آخرین پردازش: {aiStatus.last_processed_at ? fmtDateTime(aiStatus.last_processed_at) : "هنوز پردازشی ثبت نشده"}</p>
              {aiStatus.last_error && <p role="status">آخرین خطا: {aiStatus.last_error}</p>}
            </details>
            {aiStatus.intake_count >= aiStatus.intake_capacity && <p role="status" className="small" style={{ color: "var(--warn)" }}>
              ورودی خودکار به سقف ظرفیت رسیده است. هشدارهای بعدی ذخیره می‌شوند و برای تحلیل تکی یا انتخاب محدود تاریخچه در دسترس‌اند.
            </p>}
          </>}
          {(aiError || actionError) && <div className="login-error" role="alert">{actionError || aiError}</div>}
        </div>
      </section>
      <div className="security-evidence-note">
          <IconShield size={20} style={{ color: "var(--danger)" }} />
          <div>
            <b>شواهد شبکه، تصمیم آگاهانه</b>
            <p>هشدار Suricata تطابق یک قانون است؛ اثبات نفوذ نیست. نتیجهٔ هوش مصنوعی برداشت مدل از همین شواهد است.</p>
          </div>
      </div>
      <div className="card security-toolbar">
        <div className="security-filters">
          <label className="security-search"><span className="field-label">جست‌وجوی رویدادها</span>
            <input aria-label="جست‌وجو در همهٔ هشدارها" className="input" placeholder="امضای هشدار یا آدرس IP…" maxLength={200} value={q} onChange={(e) => setQ(e.target.value)} />
          </label>
          <label><span className="field-label">اولویت امنیتی</span>
          <select aria-label="شدت هشدار" className="input" style={{ width: 140 }} value={sev} onChange={(e) => { setSev(e.target.value); setPage(0); }}>
            <option value="all">همه‌ی شدت‌ها</option>
            <option value="1">بحرانی (1)</option>
            <option value="2">مهم (2)</option>
            <option value="3">متوسط (3)</option>
            <option value="4">کم (4)</option>
          </select>
          </label>
          <label><span className="field-label">وضعیت تحلیل</span>
          <select aria-label="وضعیت تحلیل همهٔ هشدارها" className="input" style={{ width: 160 }} value={aiFilter} onChange={(e) => { setAiFilter(e.target.value); setPage(0); }}>
            <option value="all">تحلیل: همه</option>
            <option value="COMPLETED">تحلیل‌شده</option>
            <option value="PENDING">در صف تحلیل</option>
            <option value="PROCESSING">در حال تحلیل</option>
            <option value="FAILED">خطای تحلیل</option>
            <option value="none">بدون تحلیل</option>
          </select>
          </label>
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
        <div className="filter-context small muted"><span>فیلترها روی تمام هشدارهای ذخیره‌شده اعمال می‌شوند.</span>
          {(sev !== "all" || aiFilter !== "all" || q) && <button className="btn ghost sm" onClick={() => { setSev("all"); setAiFilter("all"); setQ(""); setPage(0); }}>پاک‌کردن فیلترها</button>}
        </div>
      </div>

      <div className="grid-half" style={{ marginBottom: 14 }}>
        <Card title="تفکیک شدت — تمام نتایج فیلتر">
          <BarList items={bySev} />
        </Card>
        <div className="card card-pad" style={{ display: "grid", placeItems: "center" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 34, fontWeight: 800 }}>{faNum(total)}</div>
            <div className="small muted">هشدار مطابق فیلتر فعلی ({sev === "all" ? "همه" : severityLabel(Number(sev))}) در پایگاه‌داده</div>
            <div className="small muted" style={{ marginTop: 6 }}>
              تحلیل‌شده: {faNum([...analyses.values()].filter((a) => a.status === "COMPLETED").length)} ·
              در صف این صفحه: {faNum([...analyses.values()].filter((a) => a.status === "PENDING").length)}
            </div>
          </div>
        </div>
      </div>

      <Card pad={false} title="هشدارهای امنیتی"
        extra={<span className="badge badge-muted">{faNum(filtered.length)} نمایش‌داده‌شده از {faNum(total)}</span>}>
        {alerts === null && !error ? <SkeletonRows rows={6} />
          : error ? <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
            : filtered.length === 0 ? (
              <EmptyState title="هشداری مطابق فیلتر نیست" hint="فیلترها را تغییر دهید یا برای دریافت رویدادهای تازه به‌روزرسانی کنید." />
            ) : (
              <div className="table-wrap">
                <table className="data security-table">
                  <thead>
                    <tr>
                      <th>شدت</th><th>امضا</th><th>منبع → مقصد</th><th>پروتکل</th><th>action</th>
                      <th>تحلیل هوش مصنوعی</th><th>زمان</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((a) => (
                      <tr key={a.id} className="clickable" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" && e.target === e.currentTarget) setDetail(a); }} onClick={() => setDetail(a)}>
                        <td>
                          <span className={`badge ${a.severity <= 1 ? "badge-danger" : a.severity === 2 ? "badge-warn" : "badge-muted"}`}>
                            {severityLabel(a.severity)}
                          </span>
                        </td>
                        <td className="small" style={{ maxWidth: 240 }}>{a.signature ?? "—"}</td>
                        <td><div className="event-path"><span className="event-endpoints"><bdi>{a.src_port != null && a.src_ip?.includes(":") ? `[${a.src_ip}]` : a.src_ip ?? "?"}{a.src_port != null ? `:${a.src_port}` : ""}</bdi><bdi>{a.dest_port != null && a.dest_ip?.includes(":") ? `[${a.dest_ip}]` : a.dest_ip ?? "?"}{a.dest_port != null ? `:${a.dest_port}` : ""}</bdi></span><span className="muted">↓</span></div></td>
                        <td className="small">{[a.proto, a.app_proto].filter(Boolean).join("/") || "—"}</td>
                        <td>
                          {a.action == null ? <span className="badge badge-muted">نامشخص</span>
                            : a.action === "blocked" || a.action === "drop" ? <span className="badge badge-danger">drop</span>
                              : <span className="badge badge-warn">allowed</span>}
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <AnalysisCell analysis={analyses.get(a.id)} unavailable={!!aiError} paused={aiStatus?.auto_enabled === false && analyses.get(a.id)?.origin !== "manual"} onOpen={() => setDetail(a)} />
                          <button className="btn ghost" disabled={busy !== null || !!aiError}
                            aria-label={`تحلیل با هوش مصنوعی هشدار ${a.id}`}
                            onClick={() => {
                              const state = analyses.get(a.id)?.status;
                              const paused = state === "PENDING" && aiStatus?.auto_enabled === false && analyses.get(a.id)?.origin !== "manual";
                              if (state && state !== "FAILED" && !paused) setDetail(a);
                              else void analyze(a.id);
                            }}>
                            {busy === a.id ? <><MiniSpinner />ثبت درخواست…</> : analyses.get(a.id)?.status === "FAILED" ? "تلاش دوباره" : analyses.get(a.id)?.status === "COMPLETED" ? "نمایش نتیجه" : analyses.get(a.id)?.status === "PROCESSING" ? "پیگیری تحلیل" : "تحلیل با هوش مصنوعی"}
                          </button>
                        </td>
                        <td className="small muted" title={fmtDateTime(a.ts)}>{fmtAgo(a.ts)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
      </Card>
      <div className="pagination row wrap" style={{ marginTop: 12 }}>
        <span className="small muted">صفحهٔ {faNum(page + 1)} از {faNum(Math.max(1, Math.ceil(total / pageSize)))} · {faNum(filtered.length)} ردیف در این صفحه</span>
        <div className="spacer" />
        <button className="btn sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>صفحهٔ قبل</button>
        <button className="btn sm" disabled={(page + 1) * pageSize >= total} onClick={() => setPage((p) => p + 1)}>صفحهٔ بعد</button>
      </div>

      {detail && (
        <Dialog title={`هشدار #${detail.id} — شواهد و تحلیل`} onClose={() => setDetail(null)} wide busy={busy !== null}>
            <div className="row" style={{ marginBottom: 10, gap: 10 }}>
              <IconAlert size={18} style={{ color: "var(--danger)" }} />
              <div className="spacer" />
              <span className={`badge ${detail.severity <= 2 ? "badge-danger" : "badge-muted"}`}>{severityLabel(detail.severity)}</span>
            </div>

            {actionError && <div className="login-error" role="alert" style={{ marginBottom: 12 }}>{actionError}</div>}
            {detailAnalysis && !aiError && (
              <div className="card card-pad" style={{ background: "var(--bg-card-2)", marginBottom: 12 }}>
                <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                  <b>تحلیل هوش مصنوعی</b>
                  <span className={`badge ${detailAnalysis.status === "COMPLETED" ? "badge-ok" : detailAnalysis.status === "FAILED" ? "badge-danger" : "badge-muted"}`}>
                    {analysisStatusFa[detailAnalysis.status]}
                  </span>
                  {detailAnalysis.model && <span className="small muted">{detailAnalysis.model}</span>}
                  <div className="spacer" />
                  {(detailAnalysis.status === "COMPLETED" || detailAnalysis.status === "FAILED" || detailPaused) && <button
                    className="btn"
                    disabled={busy !== null}
                    onClick={() => { if (detailAnalysis.status === "COMPLETED") void reanalyze(detail.id); else void analyze(detail.id); }}
                  >
                    {busy === detail.id ? <><MiniSpinner />ثبت درخواست…</> : detailAnalysis.status === "COMPLETED" ? "⟳ تحلیل مجدد" : detailPaused ? "تحلیل تکی این هشدار" : "تلاش دوباره برای این هشدار"}
                  </button>}
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
                  <div className="small muted">تحلیل در صف/در حال اجراست.{detailAnalysis.error && ` خطا: ${detailAnalysis.error}`}</div>
                )}
                {detailAnalysis.job_id && <div className="small technical">job_id={detailAnalysis.job_id}</div>}
              </div>
            )}
            {!detailAnalysis && !aiError && <button className="btn primary" style={{ marginBottom: 16 }} disabled={busy !== null} onClick={() => { void analyze(detail.id); }}>
              {busy === detail.id ? <><MiniSpinner />ثبت درخواست…</> : "تحلیل تکی این هشدار"}
            </button>}
            {aiError && <div className="login-error" role="alert">وضعیت تحلیل قابل دریافت نیست: {aiError}</div>}

            <div className="small muted" style={{ marginBottom: 4 }}>شواهد خام Suricata:</div>
            <pre className="code-block" style={{ maxHeight: 280 }}>{JSON.stringify(detail, null, 2)}</pre>
            <div className="row" style={{ marginTop: 14 }}>
              <TechChip>{`alert_id=${detail.id}`}</TechChip>
              <div className="spacer" />
              <button className="btn ghost" disabled={busy !== null} onClick={() => setDetail(null)}>بستن</button>
            </div>
        </Dialog>
      )}
    </div>
  );
}
