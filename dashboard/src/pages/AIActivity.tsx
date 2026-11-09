/** AI Activity Monitor: real activity of the local LLM (Msty).
 *
 * Every record comes from `ai_activity` rows written by the actual request
 * pipeline — no synthetic progress stages, no fake counters. Stages that
 * never happened (e.g. streaming first token on a non-streaming model) are
 * never shown.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import { faNum, fmtAgo, fmtDateTime } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/ui";

/* ---- types ------------------------------------------------------------- */

interface ActivityRow {
  request_id: string;
  task_type: string;
  refs?: { alert_id?: number; investigation_id?: number; target_ip?: string; [k: string]: unknown }[];
  model: string | null;
  prompt_version: string | null;
  status: string;
  context_summary: string | null;
  refs_list?: unknown;
  tool_calls?: unknown;
  outcome_summary: string | null;
  error: string | null;
  created_at: string;
  sent_at: string | null;
  first_token_at: string | null;
  first_token_ms: number | null;
  final_at: string | null;
  duration_ms: number | null;
  streaming: number | null;
  timeline?: TimelineEntry[];
}

interface Summary {
  counts: Record<string, number>;
  avg_duration_ms: number | null;
  last_final_at: string | null;
  last_created_at: string | null;
  last_error: { error: string; final_at: string } | null;
  recent_errors: { error: string; final_at: string }[];
  queue: { alert_analysis_pending_and_running: number };
  model: string | null;
  llm_enabled: boolean;
}

const TASK_LABEL: Record<string, string> = {
  alert_analysis: "تحلیل هشدار (تکی)",
  alert_analysis_batch: "تحلیل گروهی هشدارها",
  investigation: "بررسی هوشمند",
};

const STAGE_LABEL: Record<string, string> = {
  REQUEST_CREATED: "ساخت رکورد",
  QUEUED: "در صف ارسال",
  CONTEXT_PREPARED: "آماده‌سازی زمینه",
  SENT_TO_LLM: "ارسال به مدل (LLM)",
  FIRST_TOKEN_RECEIVED: "دریافت اولین توکن",
  GENERATING: "تولید پاسخ",
  TOOL_REQUESTED: "درخواست ابزار",
  TOOL_COMPLETED: "اجرای ابزار",
  RESPONSE_RECEIVED: "دریافت پاسخ",
  PERSISTED: "ذخیره نتیجه",
  STREAM_FINISHED: "پایان جریان پاسخ",
};

const FINISH_LABEL: Record<string, string> = {
  stop: "پایان کامل (stop)",
  length: "بریده‌شده به‌دلیل محدودیت توکن",
  timeout: "پایان مهلت",
  content_filter: "فیلتر محتوا",
};

const STATUS_TONE: Record<string, string> = {
  RUNNING: "badge-accent",
  COMPLETED: "badge-ok",
  FAILED: "badge-danger",
  TIMEOUT: "badge-danger",
};

function statusLabel(s: string): string {
  const map: Record<string, string> = {
    RUNNING: "در حال اجرا", COMPLETED: "تکمیل", FAILED: "ناموفق", TIMEOUT: "پایان مهلت",
  };
  return map[s] ?? s;
}

function fmtMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${faNum(Math.round(ms))} میلی‌ثانیه`;
  return `${faNum(Math.round(ms / 100) / 10)} ثانیه`;
}

interface TimelineEntry {
  stage: string;
  at: string;
  provider?: string;
  model?: string;
  finish_reason?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  first_token_ms?: number;
  streaming?: boolean;
}

function entryExtras(e: TimelineEntry): string {
  const bits: string[] = [];
  if (e.provider && e.stage === "SENT_TO_LLM") bits.push(`provider: ${e.provider}`);
  if (e.model && e.stage === "SENT_TO_LLM") bits.push(`model: ${e.model}`);
  if (e.finish_reason) {
    bits.push(`finish_reason: ${FINISH_LABEL[e.finish_reason] ?? e.finish_reason}`);
  }
  if (e.prompt_tokens !== undefined) bits.push(`توکن ورودی: ${faNum(e.prompt_tokens)}`);
  if (e.completion_tokens !== undefined) {
    bits.push(`توکن خروجی: ${faNum(e.completion_tokens)}`);
  }
  return bits.join(" · ");
}

/* ---- summary strip ------------------------------------------------------ */

function SummaryCards({ summary }: { summary: Summary | null }) {
  const counts = summary?.counts ?? {};
  const items: { label: string; value: number; cls: string }[] = [
    { label: "در حال اجرا", value: counts["RUNNING"] ?? 0, cls: "badge-accent" },
    { label: "تکمیل‌شده", value: counts["COMPLETED"] ?? 0, cls: "badge-ok" },
    { label: "ناموفق", value: counts["FAILED"] ?? 0, cls: "badge-danger" },
    { label: "پایان مهلت", value: counts["TIMEOUT"] ?? 0, cls: "badge-danger" },
  ];
  return (
    <div className="stat-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12 }}>
      {items.map((it) => (
        <div key={it.label} className="card card-pad" style={{ padding: "12px 14px" }}>
          <div className="row" style={{ gap: 8 }}>
            <span className={`badge ${it.cls}`}><span className="dot" />{faNum(it.value)}</span>
            <span className="small muted">{it.label}</span>
          </div>
        </div>
      ))}
      <div className="card card-pad" style={{ padding: "12px 14px" }}>
        <div className="small muted">میانگین زمان پاسخ</div>
        <div style={{ fontWeight: 700 }}>{fmtMs(summary?.avg_duration_ms)}</div>
      </div>
      <div className="card card-pad" style={{ padding: "12px 14px" }}>
        <div className="small muted">در صف تحلیل</div>
        <div style={{ fontWeight: 700 }}>{faNum(summary?.queue?.alert_analysis_pending_and_running ?? 0)}</div>
      </div>
      <div className="card card-pad" style={{ padding: "12px 14px" }}>
        <div className="small muted">وضعیت مدل</div>
        <div style={{ fontWeight: 700 }}>
          {summary?.llm_enabled ? (
            <span className="badge badge-ok"><span className="dot" />فعال</span>
          ) : (
            <span className="badge badge-muted"><span className="dot" />غیرفعال</span>
          )}
        </div>
        {summary?.model && <div className="small technical muted" style={{ marginTop: 2 }}>{summary.model}</div>}
      </div>
    </div>
  );
}

/* ---- timeline detail ---------------------------------------------------- */

function TimelineDetail({ requestId }: { requestId: string }) {
  const [row, setRow] = useState<ActivityRow | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        setErr(null);
        const d = await api.get<ActivityRow>(`/api/admin/v1/ai-activity/${requestId}`);
        if (alive) setRow(d);
      } catch (e) {
        setErr(e instanceof ApiError ? e.detail : "بارگیری جزئیات ناموفق بود");
      }
    })();
    return () => { alive = false; };
  }, [requestId]);

  if (err) return <div className="small" style={{ color: "var(--danger)" }}>{err}</div>;
  if (!row) return <div className="small muted">…</div>;

  const timeline = row.timeline ?? [];
  return (
    <div style={{ marginTop: 10, padding: "revert", borderTop: "1px solid var(--border)" }}>
      <div className="small muted" style={{ marginBottom: 6 }}>
        شناسه درخواست: <span className="technical">{row.request_id}</span>
        {row.prompt_version && <> · نسخه پرامپت: <span className="technical">{row.prompt_version}</span></>}
        {row.first_token_ms !== null && row.first_token_ms !== undefined && (
          <> · اولین توکن پس از {fmtMs(row.first_token_ms)}{row.streaming === 1 ? " (streaming)" : ""}</>
        )}
      </div>
      {timeline.length === 0 ? (
        <div className="small muted">خط زمانی ثبت نشده است.</div>
      ) : (
        <ol style={{ margin: 0, paddingInlineStart: 18 }}>
          {timeline.map((e, i) => {
            const extras = entryExtras(e);
            return (
              <li key={i} className="small">
                <b>{STAGE_LABEL[e.stage] ?? e.stage}</b>
                <span className="muted"> — {fmtDateTime(e.at)}</span>
                {extras && <div className="technical muted" style={{ fontSize: 11 }}>{extras}</div>}
              </li>
            );
          })}
        </ol>
      )}
      {row.context_summary && (
        <div style={{ marginTop: 8 }}>
          <div className="small muted">زمینه‌ی ارسال‌شده (فشرده):</div>
          <pre className="technical small" style={{ whiteSpace: "pre-wrap", margin: 0, maxHeight: 120, overflow: "auto" }}>
            {row.context_summary}
          </pre>
        </div>
      )}
      {row.outcome_summary && (
        <div className="small" style={{ marginTop: 8 }}>
          <b>خروجی:</b> {row.outcome_summary}
        </div>
      )}
      {row.error && (
        <div className="small" style={{ marginTop: 8, color: "var(--danger)" }}>
          <b>خطا:</b> {row.error}
        </div>
      )}
    </div>
  );
}

/* ---- list row ----------------------------------------------------------- */

function ActivityItem({ row }: { row: ActivityRow }) {
  const [open, setOpen] = useState(false);
  const label = TASK_LABEL[row.task_type] ?? row.task_type;
  const refs = (row.refs ?? []).map((r) => {
    if (r.alert_id !== undefined) return `هشدار #${faNum(r.alert_id)}`;
    if (r.investigation_id !== undefined) return `بررسی #${faNum(r.investigation_id)}`;
    if (r.target_ip) return r.target_ip;
    return null;
  }).filter(Boolean).join("، ");

  return (
    <li className="card" style={{ padding: "10px 14px", marginBottom: 8 }}>
      <div
        className="row"
        style={{ gap: 10, cursor: "pointer", flexWrap: "wrap" }}
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
      >
        <span className="small muted" style={{ minWidth: 130 }}>{fmtAgo(row.created_at)}</span>
        <b className="small">{label}</b>
        {refs && <span className="small muted">{refs}</span>}
        <span className={`badge ${(STATUS_TONE[row.status]) ?? "badge-muted"}`}>
          <span className="dot" />{statusLabel(row.status)}
        </span>
        <div className="spacer" />
        <span className="small muted">مدت: {fmtMs(row.duration_ms)}</span>
        <button
          className="btn ghost sm"
          onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
          aria-label="جزئیات و خط زمانی"
        >
          {open ? "بستن" : "جزئیات"}
        </button>
      </div>
      {(row.outcome_summary || row.error) && (
        <div className="small muted" style={{ marginTop: 4 }}>
          {row.error ? <span style={{ color: "var(--danger)" }}>{row.error}</span> : row.outcome_summary}
        </div>
      )}
      {open && <TimelineDetail requestId={row.request_id} />}
    </li>
  );
}

/* ---- page --------------------------------------------------------------- */

export default function AIActivityPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [items, setItems] = useState<ActivityRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [taskType, setTaskType] = useState("");
  const [live, setLive] = useState(true);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const qs = new URLSearchParams();
      if (status) qs.set("status", status);
      if (taskType) qs.set("task_type", taskType);
      qs.set("limit", "80");
      const [s, d] = await Promise.all([
        api.get<Summary>("/api/admin/v1/ai-activity/summary"),
        api.get<{ items: ActivityRow[] }>(`/api/admin/v1/ai-activity?${qs.toString()}`),
      ]);
      setSummary(s);
      setItems(d.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, [status, taskType]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  useEffect(() => {
    if (timer.current) clearInterval(timer.current);
    if (!live) return;
    timer.current = setInterval(() => { void load(); }, 5000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [live, load]);

  const anyFilter = status !== "" || taskType !== "";

  return (
    <div>
      <Card
        title="فعالیت واقعی مدل هوش مصنوعی"
        extra={
          <>
            <label className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
              به‌روزرسانی زنده (۵ ثانیه)
            </label>
            <button className="btn ghost sm" onClick={() => setRefresh((k) => k + 1)}>بارگیری مجدد</button>
          </>
        }
      >
        <div className="small muted">
          هر رکورد از چرخه‌ی واقعی یک درخواست LLM ساخته شده است: ساخت، ارسال به Msty،
          (در صورت پشتیبانی مدل) اولین توکن، پاسخ و ذخیره. مراحلی که واقعاً رخ نداده‌اند
          نمایش داده نمی‌شوند و هیچ زنجیره‌ی تفکر خامی ذخیره یا ارائه نمی‌شود.
        </div>
      </Card>

      <div style={{ height: 12 }} />

      {error && <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />}

      <SummaryCards summary={summary} />

      {summary?.last_error && (
        <div className="card card-pad" style={{ marginTop: 12, borderColor: "var(--danger)" }}>
          <div className="small">
            <b style={{ color: "var(--danger)" }}>آخرین خطای واقعی مدل:</b> {summary.last_error.error}
            {summary.last_error.final_at && <span className="muted"> — {fmtDateTime(summary.last_error.final_at)}</span>}
          </div>
          {(summary.recent_errors?.length ?? 0) > 1 && (
            <details style={{ marginTop: 4 }}>
              <summary className="small muted">خطاهای اخیر ({faNum(summary.recent_errors.length)})</summary>
              <ul className="small muted" style={{ margin: "6px 0 0", paddingInlineStart: 18 }}>
                {summary.recent_errors.map((e, i) => (
                  <li key={i}>{e.error} — {fmtDateTime(e.final_at)}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}

      <Card
        title="درخواست‌ها"
        extra={
          <div className="row" style={{ gap: 8 }}>
            <select
              className="input" style={{ padding: "4px 8px" }} aria-label="فیلتر وضعیت"
              value={status} onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">همه وضعیت‌ها</option>
              <option value="RUNNING">در حال اجرا</option>
              <option value="COMPLETED">تکمیل‌شده</option>
              <option value="FAILED">ناموفق</option>
              <option value="TIMEOUT">پایان مهلت</option>
            </select>
            <select
              className="input" style={{ padding: "4px 8px" }} aria-label="فیلتر نوع کار"
              value={taskType} onChange={(e) => setTaskType(e.target.value)}
            >
              <option value="">همه انواع</option>
              <option value="alert_analysis">تحلیل هشدار</option>
              <option value="alert_analysis_batch">تحلیل گروهی</option>
              <option value="investigation">بررسی هوشمند</option>
            </select>
          </div>
        }
      >
        {items === null && !error && <SkeletonRows rows={5} />}
        {items !== null && items.length === 0 && (
          <EmptyState
            title={anyFilter ? "رکوردی با این فیلترها نیست" : "هنوز فعالیتی ثبت نشده است"}
            hint={anyFilter
              ? "فیلترها را بردارید یا صبر کنید کارهای در حال اجرا ثبت شوند."
              : "وقتی تحلیل هشدار یا بررسی هوشمند آغاز شود، خط زمانی واقعی اینجاست."}
          />
        )}
        {items !== null && items.length > 0 && (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {items.map((row) => <ActivityItem key={row.request_id} row={row} />)}
          </ul>
        )}
      </Card>
    </div>
  );
}
