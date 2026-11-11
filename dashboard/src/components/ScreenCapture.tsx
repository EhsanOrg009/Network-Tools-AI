/**
 * Screenshot on demand (Phase-1 of Remote Screen): request a one-shot,
 * signed capture from the agent and display the returned PNG.
 * - Server gate: ALLOW_ADMIN_SCREENSHOT + TASK_SIGNING_KEY
 * - Agent gate: --allow-screenshot (explicit local opt-in)
 * - No persistent storage: the image lives in the bounded task result.
 * Live streaming is deliberately NOT implemented yet (separate protocol +
 * security review); this is the audited on-demand path only.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { faNum } from "../lib/format";
import { Card } from "./ui";

type Phase = "idle" | "requested" | "running" | "done" | "error";

export default function ScreenCapture({ agentId }: { agentId: string }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [meta, setMeta] = useState<{ size: number; tool?: string; at: string } | null>(null);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const version = useRef(0);
  const imageRef = useRef<string | null>(null);
  const imageRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    setPhase("idle"); setImageUrl(null); setMeta(null); setMessage(null);
    return () => {
      version.current++;
      if (pollTimer.current) clearTimeout(pollTimer.current);
      imageRequest.current?.abort();
      if (imageRef.current) URL.revokeObjectURL(imageRef.current);
      imageRef.current = null;
    };
  }, [agentId]);

  const stopPolling = () => { if (pollTimer.current) clearTimeout(pollTimer.current); };

  const fetchImage = useCallback(async (taskId: string, current: number) => {
    const controller = new AbortController();
    imageRequest.current = controller;
    const res = await fetch(`/api/admin/v1/agents/${agentId}/screenshot/${taskId}`, {
      signal: controller.signal,
      headers: { Authorization: `Bearer ${localStorage.getItem("netagent.admin_token") ?? ""}` },
    });
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      throw new Error(String((detail as { detail?: string }).detail ?? `API ${res.status}`));
    }
    const blob = await res.blob();
    if (current !== version.current) return;
    const url = URL.createObjectURL(blob);
    if (imageRef.current) URL.revokeObjectURL(imageRef.current);
    imageRef.current = url;
    setImageUrl(url);
    setMeta({ size: blob.size, at: new Date().toISOString() });
    setPhase("done");
  }, [agentId]);

  const pollTask = useCallback((taskId: string, current: number) => {
    const tick = async () => {
      if (current !== version.current) return;
      try {
        const t = await api.get<{ status: string; error: string | null }>(
          `/api/admin/v1/tasks/${taskId}`,
        );
        if (current !== version.current) return;
        if (t.status === "succeeded") {
          await fetchImage(taskId, current);
          return;
        }
        if (t.status === "failed" || t.status === "expired" || t.status === "cancelled") {
          setPhase("error");
          setMessage(t.error ?? `وضعیت تسک: ${t.status}`);
          return;
        }
        pollTimer.current = setTimeout(tick, 2000);
      } catch (e) {
        if (current !== version.current) return;
        setPhase("error");
        setMessage(e instanceof Error ? e.message : "خطای ناشناخته");
      }
    };
    void tick();
  }, [fetchImage]);

  const capture = useCallback(async () => {
    stopPolling();
    imageRequest.current?.abort();
    const current = ++version.current;
    setPhase("requested");
    setMessage(null);
    try {
      const r = await api.post<{ task_id: string; status: string }>(
        `/api/admin/v1/agents/${agentId}/screenshot`,
      );
      if (current !== version.current) return;
      setPhase("running");
      setMessage(`تسک ${r.task_id} در صف قرار گرفت؛ منتظر اجرای عامل…`);
      pollTask(r.task_id, current);
    } catch (e) {
      if (current !== version.current) return;
      setPhase("error");
      setMessage(e instanceof Error ? e.message.replace(/^API \d+/, "").trim() || e.message : "خطای ناشناخته");
    }
  }, [agentId, pollTask]);

  return (
    <Card
      title="تصویر صفحهٔ عامل"
      extra={<span className="badge badge-warn">حساس</span>}
    >
      <div className="small" style={{ lineHeight: 1.9, marginBottom: 12 }}>
        درخواست یک‌باره‌ی تصویر از <b className="technical">{agentId}</b>. فقط با فعال‌بودن
        صریح قابلیت روی عامل (<code className="technical">--allow-screenshot</code>) و سرور
        (<code className="technical">ALLOW_ADMIN_SCREENSHOT</code>). در نبود نشست گرافیکی یا
        ابزار، خطای شفاف می‌آید — نه تصویر ساختگی. زنده‌استریم فعلاً پیاده‌سازی نشده است.
      </div>
      <div className="row" style={{ gap: 10 }}>
        <button className="btn" disabled={phase === "requested" || phase === "running"}
          onClick={() => { void capture(); }}>
          {phase === "running" ? "در حال دریافت…" : "دریافت تصویر صفحه"}
        </button>
        {phase === "running" && <span className="badge badge-accent"><span className="dot pulse" />در انتظار عامل</span>}
        {phase === "error" && <span className="badge badge-danger">ناموفق</span>}
      </div>
      {message && (
        <div className="small" style={{ marginTop: 8, color: phase === "error" ? "var(--danger)" : "var(--text-2)" }}>
          {message}
        </div>
      )}
      {imageUrl && (
        <div style={{ marginTop: 12 }}>
          <img src={imageUrl} alt="تصویر صفحه‌ی endpoint" style={{ maxWidth: "100%", borderRadius: 10, border: "1px solid var(--border)" }} />
          <div className="small muted" style={{ marginTop: 6 }}>
            دریافت شد ({faNum(Math.round((meta?.size ?? 0) / 1024))} KB، {meta?.at &&
              new Date(meta.at).toLocaleTimeString("fa-IR")}) — فقط در نتیجه‌ی همین تسک نگه‌داری می‌شود.
          </div>
        </div>
      )}
    </Card>
  );
}
