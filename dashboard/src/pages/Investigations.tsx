/** AI Investigations: start new investigations + view reports of past ones. */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { AgentSummary, HostRow, Investigation } from "../lib/types";
import { faNum, fmtAgo, fmtDateTime } from "../lib/format";
import { Card, Dialog, EmptyState, ErrorState, SkeletonRows, StatusPill, TechChip } from "../components/ui";
import { IconBrain } from "../components/icons";

type Mode = "quick" | "deep";

interface JobState {
  status: string;
  error: string | null;
}

const QUESTION_PLACEHOLDERS = [
  "چرا این میزبان به ping پاسخ نمی‌دهد؟ شواهد مربوطه را جمع‌آوری کن.",
  "این میزبان را از نظر سرویس‌های فعال، سیستم‌عامل و مشکلات ارتباطی بررسی کن.",
];

/** شروع بررسی هوشمند جدید — از APIهای واقعی: همگام یا کار پس‌زمینه. */
function NewInvestigationPanel({ onStarted }: { onStarted: (invId: number | null) => void }) {
  const [open, setOpen] = useState(false);
  const [hosts, setHosts] = useState<HostRow[] | null>(null);
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [target, setTarget] = useState("");
  const [question, setQuestion] = useState("");
  const [mode, setMode] = useState<Mode>("quick");
  const [runPing, setRunPing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<JobState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!open || hosts !== null) return;
    void (async () => {
      try {
        const [h, a] = await Promise.all([
          api.get<{ items?: HostRow[] }>("/api/hosts?limit=100").catch(() => ({ items: [] })),
          api.get<{ items?: AgentSummary[] }>("/api/admin/v1/agents?limit=100")
            .catch(() => ({ items: [] })),
        ]);
        setHosts(Array.isArray(h.items) ? h.items : []);
        setAgents(Array.isArray(a.items) ? a.items : []);
      } catch {
        setHosts([]);
        setAgents([]);
      }
    })();
  }, [open, hosts]);

  useEffect(() => () => { if (pollTimer.current) clearTimeout(pollTimer.current); }, []);

  const showError = (e: unknown) =>
    setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");

  const trackJob = useCallback((jobId: string) => {
    const tick = async () => {
      try {
        const st = await api.get<JobState & { id: string }>(`/api/jobs/${jobId}`);
        setJob({ status: st.status, error: st.error ?? null });
        if (st.status === "completed" || st.status === "failed") {
          setBusy(false);
          onStarted(null);
          return;
        }
        pollTimer.current = setTimeout(tick, 3000);
      } catch (e) {
        setBusy(false);
        showError(e);
      }
    };
    void tick();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onStarted]);

  const start = useCallback(async () => {
    const trimmed = target.trim();
    if (!trimmed) {
      setError("هدف را انتخاب یا وارد کنید.");
      return;
    }
    setBusy(true);
    setError(null);
    setJob(null);
    const body: Record<string, unknown> = {
      target_ip: trimmed,
      question: question.trim() || null,
      run_ping: runPing,
    };
    try {
      if (mode === "quick") {
        const inv = await api.post<Investigation>("/api/investigations", body);
        onStarted(inv.id ?? null);
      } else {
        const res = await api.post<{ job_id: string }>("/api/jobs/investigation", body);
        trackJob(res.job_id);
      }
    } catch (e) {
      setBusy(false);
      showError(e);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, question, mode, runPing, onStarted, trackJob]);

  const targetSuggestions = useMemo(() => {
    const set = new Set<string>();
    for (const h of hosts ?? []) if (h.ip) set.add(h.ip);
    for (const a of agents ?? []) for (const ip of a.claimed_ips ?? []) set.add(ip);
    return [...set];
  }, [hosts, agents]);

  if (!open) {
    return (
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row">
          <div>
            <div style={{ fontWeight: 700 }}>شروع بررسی هوشمند جدید</div>
            <div className="small muted">
              هدف باید داخل محدوده‌ی مجاز باشد؛ هدف خارج از scope با 403 رد می‌شود.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => setOpen(true)}>+ بررسی جدید</button>
        </div>
      </div>
    );
  }

  return (
    <div className="card card-pad" style={{ marginBottom: 14 }}>
      <div className="row" style={{ marginBottom: 10 }}>
        <div>
          <div style={{ fontWeight: 700 }}>شروع بررسی هوشمند جدید</div>
          <div className="small muted">
            هدف، پرسش و حالت اجرا را انتخاب کنید؛ بررسی توسط Orchestrator موجود و با بودجه‌ی
            پیکربندی‌شده اجرا می‌شود. مدل به ابزارهای تشخیصی کنترل‌شده دسترسی دارد، نه shell.
          </div>
        </div>
        <div className="spacer" />
        <button className="btn ghost" onClick={() => { setOpen(false); setError(null); }}>بستن</button>
      </div>

      <div className="row wrap" style={{ gap: 12, alignItems: "flex-start" }}>
        <div style={{ flex: "1 1 260px" }}>
          <label className="small muted" htmlFor="inv-target">هدف (IP میزبان)</label>
          <input
            id="inv-target" className="input technical" style={{ width: "100%" }}
            list="inv-targets" placeholder="مثلاً 192.168.1.10" value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <datalist id="inv-targets">
            {targetSuggestions.map((t: string) => <option key={t} value={t} />)}
          </datalist>
          {agents && agents.length > 0 && (
            <div className="small muted" style={{ marginTop: 4 }}>
              عوامل فعال: {agents.filter((a) => a.status === "active").slice(0, 4)
                .map((a) => `${a.hostname ?? a.id} (${a.claimed_ips?.[0] ?? "?"})`).join("، ")}
            </div>
          )}
        </div>
        <div style={{ flex: "2 1 320px" }}>
          <label className="small muted" htmlFor="inv-question">پرسش (اختیاری، فارسی)</label>
          <textarea
            id="inv-question" className="input" style={{ width: "100%", minHeight: 64, resize: "vertical" }}
            placeholder={QUESTION_PLACEHOLDERS[0]} value={question}
            onChange={(e) => setQuestion(e.target.value)} maxLength={2000}
          />
        </div>
      </div>

      <div className="row wrap" style={{ gap: 14, marginTop: 12 }}>
        <label className="row small" style={{ gap: 6 }}>
          <input type="radio" checked={mode === "quick"} onChange={() => setMode("quick")} />
          <b>Quick</b> — همگام: منتظر نتیجه می‌مانیم (تا سقف مهلت بررسی)
        </label>
        <label className="row small" style={{ gap: 6 }}>
          <input type="radio" checked={mode === "deep"} onChange={() => setMode("deep")} />
          <b>Deep</b> — کار پس‌زمینه: بلافاصله job_id می‌گیریم و وضعیت را دنبال می‌کنیم
        </label>
        <label className="row small" style={{ gap: 6 }}>
          <input type="checkbox" checked={runPing} onChange={(e) => setRunPing(e.target.checked)} />
          اجازه‌ی ping محدود روی هدف
        </label>
        <div className="spacer" />
        <button className="btn" disabled={busy} onClick={() => { void start(); }}>
          {busy ? "در حال اجرا…" : "▶ Start Investigation"}
        </button>
      </div>

      {error && <div className="small" style={{ color: "var(--danger)", marginTop: 10 }}>خطا: {error}</div>}
      {job && (
        <div className="small" style={{ marginTop: 10 }}>
          وضعیت کار پس‌زمینه:{" "}
          <span className={`badge ${job.status === "completed" ? "badge-ok" : job.status === "failed" ? "badge-danger" : "badge-accent"}`}>
            {job.status}
          </span>
          {job.error && <span style={{ color: "var(--danger)" }}> — {job.error}</span>}
        </div>
      )}
    </div>
  );
}

export default function InvestigationsPage() {
  const [items, setItems] = useState<Investigation[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<Investigation | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const d = await api.get<{ items: Investigation[] }>("/api/investigations?limit=100");
      setItems(d.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconBrain size={20} style={{ color: "var(--accent-2)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>بررسی‌های هوشمند</div>
            <div className="small muted">
              تحقیقاتی که هسته‌ی مدل زبانی روی میزبان یا هشدار انجام داده. نتیجه‌ی مدل یک
              «گزارش» است، نه اقدام — هیچ عملیات مسدودسازی از این مسیر انجام نمی‌شود.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      <NewInvestigationPanel onStarted={() => setRefresh((k) => k + 1)} />

      <Card pad={false} title="فهرست بررسی‌ها">
        {items === null && !error ? <SkeletonRows rows={5} />
          : error ? <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
            : (items ?? []).length === 0 ? (
              <EmptyState title="بررسی‌ای انجام نشده"
                hint="از پنل «شروع بررسی هوشمند جدید» بالای همین صفحه اقدام کنید." />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>#</th><th>موضوع</th><th>هدف</th><th>وضعیت</th><th>اطمینان</th><th>ابزارها</th><th>شروع / پایان</th></tr>
                  </thead>
                  <tbody>
                    {(items ?? []).map((inv) => (
                      <tr key={inv.id} className="clickable" onClick={() => setDetail(inv)}>
                        <td className="small muted">{faNum(inv.id)}</td>
                        <td style={{ maxWidth: 300 }}>{inv.trigger} {inv.question ? <span className="small muted">— {inv.question.slice(0, 60)}</span> : null}</td>
                        <td><TechChip>{inv.target_ip ?? "—"}</TechChip></td>
                        <td><StatusPill state={inv.status} /></td>
                        <td className="small">{inv.confidence ?? "—"}</td>
                        <td className="small muted">{inv.iterations != null ? `${faNum(inv.iterations)} فراخوانی` : "—"}</td>
                        <td className="small muted">{fmtAgo(inv.created_at)} → {inv.finished_at ? fmtAgo(inv.finished_at) : "در جریان"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
      </Card>

      {detail && (
        <Dialog title={`گزارش بررسی #${detail.id}`} onClose={() => setDetail(null)} wide>
            <div className="row" style={{ marginBottom: 10, gap: 10 }}>
              <StatusPill state={detail.status} />
            </div>
            <dl className="two-col-defs small">
              <dt>هدف</dt><dd><TechChip>{detail.target_ip ?? "—"}</TechChip></dd>
              <dt>پرسش</dt><dd>{detail.question ?? "—"}</dd>
              <dt>شروع</dt><dd>{fmtDateTime(detail.created_at)}</dd>
              <dt>پایان</dt><dd>{fmtDateTime(detail.finished_at)}</dd>
              <dt>ابزارهای استفاده‌شده</dt><dd>{detail.iterations ?? "—"} فراخوانی</dd>
              {detail.error && (<><dt>خطا</dt><dd className="small" style={{ color: "var(--danger)" }}>{detail.error}</dd></>)}
            </dl>
            <div className="divider" />
            {detail.report_text ? (
              <pre className="code-block" style={{ maxHeight: 320, whiteSpace: "pre-wrap", direction: "rtl", textAlign: "start" }}>
                {detail.report_text}
              </pre>
            ) : (
              <EmptyState title="گزارش نهایی ثبت نشده" />
            )}
            {detail.evidence && detail.evidence.length > 0 && (
              <details style={{ marginTop: 10 }}>
                <summary className="small muted" style={{ cursor: "pointer" }}>شواهد جمع‌آوری‌شده ({detail.evidence.length})</summary>
                <pre className="code-block" style={{ marginTop: 8, maxHeight: 260 }}>{JSON.stringify(detail.evidence, null, 2)}</pre>
              </details>
            )}
            <div className="row" style={{ marginTop: 14 }}>
              <div className="spacer" />
              <button className="btn ghost" onClick={() => setDetail(null)}>بستن</button>
            </div>
        </Dialog>
      )}
    </div>
  );
}
