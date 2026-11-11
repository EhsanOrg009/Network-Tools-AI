/** AI Knowledge — persistent memory (knowledge base) of the network intelligence.
 *
 * Everything here is administrator-verifiable knowledge: either the admin
 * entered it directly (immediately APPROVED) or the AI proposed it and it
 * stays PENDING_APPROVAL until an administrator approves. The analysis
 * pipeline only ever uses APPROVED records — poisoned/suggested memory
 * cannot leak into decisions from this page.
 */

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import { usePolling } from "../lib/polling";
import { faNum, fmtDateTime, fmtAgo } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, ConfirmDialog } from "../components/ui";

/* ---- types ------------------------------------------------------------- */

interface MemoryRow {
  memory_id: string;
  title: string;
  description: string | null;
  category: string;
  scope: string;
  status: string;
  agent_id: string | null;
  host: string | null;
  process: string | null;
  service: string | null;
  network: string | null;
  source: string | null;
  created_by: string | null;
  created_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
  updated_at: string | null;
  revoke_reason: string | null;
  confidence: string | null;
  expires_at: string | null;
  hit_count: number | null;
  last_hit_at: string | null;
  question_id: string | null;
  alert_id: number | null;
}

const CATEGORIES: { value: string; label: string }[] = [
  { value: "approved_service", label: "سرویس تأییدشده" },
  { value: "known_process", label: "فرآیند شناخته‌شده" },
  { value: "known_false_positive", label: "مثبت کاذب شناخته‌شده" },
  { value: "known_network_behavior", label: "رفتار شبکه‌ای شناخته‌شده" },
  { value: "known_device", label: "دستگاه شناخته‌شده" },
  { value: "known_service", label: "سرویس شناخته‌شده" },
  { value: "incident_resolution", label: "رفع incident گذشته" },
  { value: "diagnostic_playbook", label: "پاورقی عیب‌یابی" },
];

const SCOPES: { value: string; label: string }[] = [
  { value: "agent", label: "این عامل" },
  { value: "host", label: "این میزبان" },
  { value: "process", label: "این فرآیند" },
  { value: "service", label: "این سرویس" },
  { value: "network", label: "این شبکه" },
  { value: "global", label: "سراسری" },
];

const STATUS_LABEL: Record<string, string> = {
  APPROVED: "تأییدشده",
  PENDING_APPROVAL: "در انتظار تأیید",
  REVOKED: "لغوشده",
  EXPIRED: "منقضی",
};

const STATUS_TONE: Record<string, string> = {
  APPROVED: "badge-ok",
  PENDING_APPROVAL: "badge-accent",
  REVOKED: "badge-danger",
  EXPIRED: "badge-muted",
};

function catLabel(c: string): string {
  return CATEGORIES.find((x) => x.value === c)?.label ?? c;
}

function scopeBits(m: MemoryRow): string {
  const parts: string[] = [];
  if (m.agent_id) parts.push(`عامل: ${m.agent_id}`);
  if (m.host) parts.push(`میزبان: ${m.host}`);
  if (m.process) parts.push(`فرآیند: ${m.process}`);
  if (m.service) parts.push(`سرویس: ${m.service}`);
  if (m.network) parts.push(`شبکه: ${m.network}`);
  return parts.join(" · ");
}

/* ---- memory row --------------------------------------------------------- */

function MemoryItem({
  m, onChanged,
}: { m: MemoryRow; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [reason, setReason] = useState("");

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="card" style={{ padding: "10px 14px", marginBottom: 8 }}>
      <div
        className="row" style={{ gap: 10, cursor: "pointer", flexWrap: "wrap" }}
        onClick={() => setOpen((o) => !o)} role="button" aria-expanded={open}
      >
        <b className="small">{m.title}</b>
        <span className={`badge ${STATUS_TONE[m.status] ?? "badge-muted"}`}>
          <span className="dot" />{STATUS_LABEL[m.status] ?? m.status}
        </span>
        <span className="small muted">{catLabel(m.category)}</span>
        <div className="spacer" />
        <span className="small muted">
          استفاده: {faNum(m.hit_count ?? 0)}
          {m.last_hit_at && <> · آخرین: {fmtAgo(m.last_hit_at)}</>}
        </span>
      </div>
      {scopeBits(m) && (
        <div className="small technical muted" style={{ marginTop: 4 }}>
          {scopeBits(m)}
        </div>
      )}
      {err && (
        <div className="small" style={{ marginTop: 6, color: "var(--danger)" }}>{err}</div>
      )}
      {open && (
        <div style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 8 }}>
          {m.description && (
            <div className="small" style={{ whiteSpace: "pre-wrap" }}>{m.description}</div>
          )}
          <div className="small muted" style={{ marginTop: 6 }}>
            شناسه: <span className="technical">{m.memory_id}</span>
            {m.source && <> · منبع: {m.source === "administrator" ? "مدیر شبکه" : m.source}</>}
            {m.created_by && <> · ثبت: {m.created_by}</>}
            {m.created_at && <> · {fmtDateTime(m.created_at)}</>}
            {m.approved_by && <> · تأیید: {m.approved_by} ({m.approved_at ? fmtDateTime(m.approved_at) : "—"})</>}
            {m.confidence && <> · اطمینان: {m.confidence}</>}
            {m.expires_at && <> · انقضا: {fmtDateTime(m.expires_at)}</>}
            {m.revoke_reason && <> · دلیل لغو: {m.revoke_reason}</>}
          </div>
          <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap" }}>
            {m.status === "PENDING_APPROVAL" && (
              <button
                className="btn sm" disabled={busy}
                onClick={() => void act(() => api.post(`/api/admin/v1/ai-memories/${m.memory_id}/approve`))}
              >
                تأیید و فعال‌سازی
              </button>
            )}
            {(m.status === "APPROVED" || m.status === "PENDING_APPROVAL") && (
              <button
                className="btn danger sm" disabled={busy}
                onClick={() => setRevokeOpen(true)}
              >
                لغو حافظه
              </button>
            )}
            <button
              className="btn ghost sm" disabled={busy}
              onClick={() => setOpen(false)}
            >
              بستن جزئیات
            </button>
          </div>
        </div>
      )}
      <ConfirmDialog
        open={revokeOpen}
        title="لغو این حافظه؟"
        message={`حافظه «${m.title}» از همه‌ی تحلیل‌های بعدی حذف می‌شود؛ رکورد برای حسابرسی باقی می‌ماند.`}
        busy={busy}
        danger
        onConfirm={() => void act(async () => {
          await api.post(`/api/admin/v1/ai-memories/${m.memory_id}/revoke`,
            reason.trim() ? { reason: reason.trim() } : {});
          setRevokeOpen(false);
          setReason("");
        })}
        onCancel={() => { setRevokeOpen(false); setErr(null); }}
      />
    </li>
  );
}

/* ---- create form -------------------------------------------------------- */

function CreateMemoryForm({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({
    title: "", description: "", category: "approved_service", scope: "agent",
    agent_id: "", host: "", process: "", service: "", network: "",
    confidence: "", expires_at: "",
  });

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  if (!open) {
    return (
      <button className="btn sm" onClick={() => setOpen(true)}>
        + ثبت دانش جدید
      </button>
    );
  }

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.post("/api/admin/v1/ai-memories", {
        title: form.title.trim(),
        description: form.description.trim() || null,
        category: form.category,
        scope: form.scope,
        agent_id: form.agent_id.trim() || null,
        host: form.host.trim() || null,
        process: form.process.trim() || null,
        service: form.service.trim() || null,
        network: form.network.trim() || null,
        confidence: form.confidence.trim() || null,
        expires_at: form.expires_at.trim() || null,
        evidence: [],
      });
      setOpen(false);
      setForm((f) => ({ ...f, title: "", description: "" }));
      onCreated();
    } catch (e) {
      setErr(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card card-pad" style={{ padding: "12px 14px" }}>
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <input className="input" style={{ minWidth: 260 }} placeholder="عنوان حافظه (حداقل ۳ نویسه)"
          value={form.title} onChange={set("title")} />
        <select className="input" style={{ width: 190 }} value={form.category} onChange={set("category")} aria-label="دسته‌بندی">
          {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>
        <select className="input" style={{ width: 140 }} value={form.scope} onChange={set("scope")} aria-label="محدوده‌ی اعتبار">
          {SCOPES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
      </div>
      <textarea
        className="input" rows={2}
        style={{ marginTop: 8, width: "100%" }}
        placeholder="توضیح: چرا این رفتار مجاز/شناخته‌شده است؟ (به‌عنوان زمینه به مدل تحلیل‌گر داده می‌شود)"
        value={form.description} onChange={set("description")}
      />
      <div className="row" style={{ gap: 10, marginTop: 8, flexWrap: "wrap" }}>
        <input className="input" style={{ width: 150 }} placeholder="شناسه عامل" value={form.agent_id} onChange={set("agent_id")} />
        <input className="input" style={{ width: 160 }} placeholder="می‌زبان / آی‌پی" value={form.host} onChange={set("host")} />
        <input className="input" style={{ width: 140 }} placeholder="فرآیند" value={form.process} onChange={set("process")} />
        <input className="input" style={{ width: 140 }} placeholder="سرویس" value={form.service} onChange={set("service")} />
        <input className="input" style={{ width: 170 }} placeholder="شبکه (CIDR)" value={form.network} onChange={set("network")} />
      </div>
      <div className="row" style={{ gap: 10, marginTop: 8, flexWrap: "wrap" }}>
        <input className="input" style={{ width: 150 }} placeholder="اطمینان (اختیاری)" value={form.confidence} onChange={set("confidence")} />
        <input className="input" style={{ width: 210 }} placeholder="انقضا ISO (خالی = دائمی)" value={form.expires_at} onChange={set("expires_at")} />
        <div className="spacer" />
        <button className="btn ghost sm" disabled={busy} onClick={() => { setOpen(false); setErr(null); }}>انصراف</button>
        <button className="btn sm" disabled={busy || form.title.trim().length < 3} onClick={() => void submit()}>
          {busy ? "در حال ثبت…" : "ثبت بلافاصله‌فعال"}
        </button>
      </div>
      {err && <div className="small" style={{ marginTop: 8, color: "var(--danger)" }}>{err}</div>}
      <div className="small muted" style={{ marginTop: 8 }}>
        این مسیر مستقیم مدیر است؛ رکورد با وضعیت <b>APPROVED</b> ثبت می‌شود. حافظه‌های پیشنهادی AI
        از بقیه مسیرها حق عبور ندارند و پیش از تأیید شما در هر تحلیلی استفاده نمی‌شوند.
      </div>
    </div>
  );
}

/* ---- ask the model card ------------------------------------------------- */

interface QuestionRow {
  question_id: string;
  question: string;
  status: string;
  answer: string | null;
  answer_meta?: { confidence?: string | null; memory_proposal?: unknown } | null;
  memory_proposal_ids?: string[] | null;
  error: string | null;
  asked_at: string | null;
  duration_ms: number | null;
}

const Q_STATUS: Record<string, { label: string; tone: string }> = {
  PENDING: { label: "در انتظار پاسخ", tone: "badge-accent" },
  ANSWERED: { label: "پاسخ داده شد", tone: "badge-ok" },
  FAILED: { label: "ناموفق", tone: "badge-danger" },
};

function AskModel({ onMemoryChanged }: { onMemoryChanged: () => void }) {
  const [items, setItems] = useState<QuestionRow[] | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const d = await api.get<{ items: QuestionRow[] }>(
        "/api/admin/v1/ai-questions?limit=20"
      );
      setItems(d.items);
    } catch (e) {
      setErr(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const ask = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.post("/api/admin/v1/ai-questions", { question: text.trim() });
      setText("");
      await load();
      onMemoryChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <input
          className="input" style={{ flex: 1, minWidth: 260 }}
          placeholder="مثلاً: هشدارهای تکراری DNS روی این عامل طبیعی است؟"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && text.trim().length >= 3 && !busy) void ask(); }}
          disabled={busy}
        />
        <button className="btn sm" disabled={busy || text.trim().length < 3} onClick={() => void ask()}>
          {busy ? "در حال پرسش…" : "پرسش"}
        </button>
      </div>
      {err && <div className="small" style={{ marginTop: 8, color: "var(--danger)" }}>{err}</div>}
      <div className="small muted" style={{ marginTop: 8 }}>
        هر پرسش همگام پاسخ می‌گیرد و هیچ ابزاری اجرا نمی‌شود. اگر مدل دانش جدیدی پیشنهاد
        کند، ثبت آن فقط به‌صورت حافظه‌ی «در انتظار تأیید» است و فعال‌سازی با دست شماست.
      </div>
      <ul style={{ listStyle: "none", margin: 0, padding: 0, marginTop: 10 }}>
        {(items ?? []).map((q) => {
          const st = Q_STATUS[q.status] ?? { label: q.status, tone: "badge-muted" };
          return (
            <li key={q.question_id} className="card" style={{ padding: "8px 12px", marginBottom: 6 }}>
              <div className="row small" style={{ gap: 8, flexWrap: "wrap" }}>
                <b>{q.question}</b>
                <div className="spacer" />
                <span className={`badge ${st.tone}`}><span className="dot" />{st.label}</span>
                {q.memory_proposal_ids && q.memory_proposal_ids.length > 0 && (
                  <span className="badge badge-accent">
                    <span className="dot" />پیشنهاد حافظه: {faNum(q.memory_proposal_ids.length)}
                  </span>
                )}
              </div>
              {(q.answer || q.error) && (
                <div className="small" style={{ marginTop: 4 }}>
                  {q.error
                    ? <span style={{ color: "var(--danger)" }}>{q.error}</span>
                    : q.answer}
                </div>
              )}
            </li>
          );
        })}
        {items !== null && items.length === 0 && items && (
          <li className="small muted">هنوز پرسشی ثبت نشده است.</li>
        )}
      </ul>
    </>
  );
}

/* ---- page --------------------------------------------------------------- */

export default function AIKnowledgePage() {
  const [items, setItems] = useState<MemoryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [live, setLive] = useState(false);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      setError(null);
      const qs = new URLSearchParams();
      if (status) qs.set("status", status);
      if (category) qs.set("category", category);
      qs.set("limit", "200");
      const d = await api.get<{ items: MemoryRow[] }>(`/api/admin/v1/ai-memories?${qs.toString()}`, { signal });
      if (signal?.aborted) return;
      setItems(d.items);
    } catch (e) {
      if (signal?.aborted) return;
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, [status, category]);

  usePolling(load, 10000, live, refreshKey);

  const pending = (items ?? []).filter((m) => m.status === "PENDING_APPROVAL").length;
  const anyFilter = status !== "" || category !== "";

  return (
    <div>
      <Card
        title="حافظه‌ی دائمیِ هوش مصنوعی (دانش پایه)"
        extra={
          <>
            <label className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
              به‌روزرسانی زنده (۱۰ ثانیه)
            </label>
            <button className="btn ghost sm" onClick={() => setRefresh((k) => k + 1)}>بارگیری مجدد</button>
          </>
        }
      >
        <div className="small muted">
          این پایگاه، «حافظه» تحلیل‌گر شبکه است: دانش بازبینی‌شده‌ی شما که هر تحلیلی باید به آن
          استناد کند (مثلاً «سرویس Tor روی این عامل عمدی است»). حافظه‌ی پیچیده‌شده (پیشنهاد مدل
          یا متن لاگ) تا تأیید شما هیچ‌گاه در تحلیل استفاده نمی‌شود و مدل هم به سیستم تأیید و
          حذف حافظه دسترسی ندارد.
        </div>
        {pending > 0 && (
          <div style={{ marginTop: 8 }}>
            <span className="badge badge-accent"><span className="dot" />
              {faNum(pending)} حافظه در انتظار تأیید شماست
            </span>
          </div>
        )}
      </Card>

      <div style={{ height: 12 }} />

      {error && <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />}

      <Card
        title="پرسش هوشمند از مدل"
        extra={null}
      >
        <AskModel onMemoryChanged={() => setRefresh((k) => k + 1)} />
      </Card>

      <div style={{ height: 12 }} />

      <Card
        title="ثبت حافظه"
        extra={null}
      >
        <CreateMemoryForm onCreated={() => setRefresh((k) => k + 1)} />
      </Card>

      <div style={{ height: 12 }} />

      <Card
        title="همه‌ی حافظه‌ها"
        extra={
          <div className="row" style={{ gap: 8 }}>
            <select className="input" style={{ padding: "4px 8px" }} aria-label="فیلتر وضعیت"
              value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">همه وضعیت‌ها</option>
              <option value="APPROVED">تأییدشده</option>
              <option value="PENDING_APPROVAL">در انتظار تأیید</option>
              <option value="REVOKED">لغوشده</option>
              <option value="EXPIRED">منقضی</option>
            </select>
            <select className="input" style={{ padding: "4px 8px" }} aria-label="فیلتر دسته"
              value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">همه دسته‌ها</option>
              {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
          </div>
        }
      >
        {items === null && !error && <SkeletonRows rows={5} />}
        {items !== null && items.length === 0 && (
          <EmptyState
            title={anyFilter ? "حافظه‌ای با این فیلترها نیست" : "حافظه‌ای ثبت نشده است"}
            hint="ثبت اسناد بازبینی‌شده (سرویس‌های عمدی، مثبت‌های کاذب شناخته‌شده، دستگاه‌های معروف) کم‌هشدار بودن تحلیل‌ها را بالا می‌برد."
          />
        )}
        {items !== null && items.length > 0 && (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {items.map((m) => (
              <MemoryItem key={m.memory_id} m={m} onChanged={() => setRefresh((k) => k + 1)} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
