/**
 * Real Remote Python Console — talks to /api/admin/v1/console/* only.
 * Interpreter state persists across commands on the backend (one live
 * REPL per session on the endpoint, driven through the signed task channel).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { ConsoleSession, ConsoleCommand as Cmd } from "../lib/types";
import { faNum, fmtTime } from "../lib/format";
import { MiniSpinner, TechChip } from "./ui";
import { useToast } from "./toast";
import { IconTerminal, IconX, IconCopy } from "./icons";

interface Props {
  agentId: string;
  agentLabel: string;
}

type OutLine = { kind: "code" | "stdout" | "stderr" | "error" | "repr" | "info" | "system"; text: string; ms?: number; at?: string | null };

export function RemoteConsole({ agentId, agentLabel }: Props) {
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [commands, setCommands] = useState<Cmd[]>([]);
  const [code, setCode] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [pollErr, setPollErr] = useState<string | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);
  const toast = useToast();

  /* --- create / attach session ------------------------------------------- */

  const openSession = useCallback(async () => {
    setConnecting(true);
    setPollErr(null);
    try {
      const s = await api.post<ConsoleSession>(
        `/api/admin/v1/agents/${agentId}/console/sessions`,
        { agent_id: agentId },
      );
      setSession(s);
      toast.push("درخواست ایجاد نشست کنسول ثبت شد.", "success");
    } catch (e) {
      setPollErr(e instanceof ApiError ? e.detail : "ایجاد نشست ناموفق بود.");
    } finally {
      setConnecting(false);
    }
  }, [agentId, toast]);

  const terminate = useCallback(async () => {
    if (!session) return;
    try {
      await api.post(`/api/admin/v1/console/sessions/${session.id}/terminate`, {});
    } catch (e) {
      if (!(e instanceof ApiError && (e.status === 404 || e.status === 410))) {
        const message = e instanceof ApiError ? e.detail : "بستن نشست ناموفق بود؛ دوباره تلاش کنید.";
        setPollErr(message);
        toast.push(message, "error");
        return;
      }
    }
    setSession(null);
    setCommands([]);
    setPollErr(null);
    toast.push("نشست کنسول بسته شد.", "info");
  }, [session, toast]);

  useEffect(() => {
    setSession(null);
    setCommands([]);
    setCode("");
    setPollErr(null);
  }, [agentId]);

  /* --- poll session + running commands ------------------------------------ */

  const hasRunning = commands.some((c) => c.status === "queued" || c.status === "dispatched" || c.status === "running");

  useEffect(() => {
    if (!session) return;
    let stop = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const d = await api.get<{ session: ConsoleSession; commands: Cmd[] }>(
          `/api/admin/v1/console/sessions/${session.id}?commands_limit=200`,
        );
        if (stop) return;
        setCommands(d.commands ?? []);
        setSession((s) => (s ? { ...s, status: d.session.status } : d.session));
        setPollErr(null);
        const delay = (d.commands ?? []).some(
          (c) => ["queued", "dispatched", "running"].includes(c.status),
        ) ? 800 : 4000;
        timer = window.setTimeout(poll, delay);
      } catch (e) {
        if (stop) return;
        const err = e instanceof ApiError ? e : null;
        if (err && (err.status === 404 || err.status === 410)) {
          setSession(null);
          setPollErr("نشست تمام شد (انقضای idle یا بسته‌شدن توسط سرور).");
          return;
        }
        setPollErr(err?.detail ?? "ارتباط با سرور قطع شد؛ تلاش دوباره…");
        timer = window.setTimeout(poll, 4000);
      }
    };
    void poll();
    return () => { stop = true; if (timer) window.clearTimeout(timer); };
  }, [session?.id]);

  /* --- submit -------------------------------------------------------------- */

  async function execute() {
    if (!session || !code.trim()) return;
    const thisCode = code;
    setCode("");
    try {
      await api.post(`/api/admin/v1/console/sessions/${session.id}/commands`, { code: thisCode });
      setCommands((c) => [
        ...c,
        {
          id: "optimistic",
          session_id: session.id,
          seq: c.length + 1,
          status: "queued",
          code: thisCode,
          submitted_at: new Date().toISOString(),
          finished_at: null,
          stdout: null,
          stderr: null,
          result_repr: null,
          error: null,
          duration_ms: null,
          truncated: false,
        },
      ]);
    } catch (e) {
      toast.push(e instanceof ApiError ? e.detail : "ارسال دستور ناموفق بود.", "error");
    } finally {
      taRef.current?.focus();
    }
  }

  async function cancelCommand(cmd: Cmd) {
    if (!session) return;
    try {
      await api.post(`/api/admin/v1/console/sessions/${session.id}/commands/${cmd.id}/cancel`, {});
      toast.push("درخواست لغو ارسال شد.", "info");
    } catch (e) {
      toast.push(e instanceof ApiError ? e.detail : "لغو ناموفق بود.", "error");
    }
  }

  useEffect(() => {
    if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight;
  }, [commands]);

  function fmtOut(c: Cmd): OutLine[] {
    const lines: OutLine[] = [];
    lines.push({ kind: "code", text: `>>> ${c.code}`, at: c.submitted_at });
    if (c.stdout) lines.push({ kind: "stdout", text: c.stdout.replace(/\n$/, "") });
    if (c.stderr) lines.push({ kind: "stderr", text: c.stderr.replace(/\n$/, "") });
    if (c.error) lines.push({ kind: "error", text: c.error });
    if (c.result_repr) lines.push({ kind: "repr", text: c.result_repr });
    if (c.status === "running") lines.push({ kind: "info", text: "… در حال اجرا" });
    lines.push({ kind: "info", text: `${c.status === "queued" || c.status === "dispatched" ? "در صف" : "خارج"}, ${c.duration_ms ? `${faNum(Math.round(c.duration_ms))}ms` : ""}`.trimEnd() });
    return lines;
  }

  const colorFor: Record<OutLine["kind"], string> = {
    code: "var(--accent)",
    stdout: "#d5e2f7",
    stderr: "var(--warn)",
    error: "var(--danger)",
    repr: "var(--ok)",
    info: "#64719b",
    system: "#64719b",
  };

  const allText = commands.flatMap(fmtOut).map((l) => l.text).join("\n");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div className="card card-pad">
        <div className="row wrap" style={{ gap: 12 }}>
          <div className="stat-icon" style={{ background: "var(--accent-soft)", color: "var(--accent)", width: 34, height: 34 }}>
            <IconTerminal size={17} />
          </div>
          <div>
            <div style={{ fontWeight: 700 }}>کنسول پایتون از راه دور</div>
            <div className="small muted">
              اجرای دستورها روی عامل <TechChip>{agentId}</TechChip> {agentLabel && `(${agentLabel})`} — همان مفسرِ زنده
            </div>
          </div>
          <div className="spacer" />
          {!session ? (
            <button className="btn primary" disabled={connecting} onClick={openSession}>
              {connecting ? <MiniSpinner /> : "اتصال به عامل و ساخت نشست"}
            </button>
          ) : (
            <>
              <span className={`badge ${session.status === "active" ? "badge-ok" : "badge-warn"}`}>
                <span className={`dot${session.status === "active" ? " pulse" : ""}`} />
                نشست {session.status === "active" ? "فعال" : session.status} — <span className="technical">{session.id}</span>
              </span>
              <button className="btn danger sm" onClick={terminate}><IconX size={14} /> بستن نشست</button>
            </>
          )}
        </div>
        <div className="small muted" style={{ marginTop: 8 }}>
          متغیرها و importها بین دستورها حفظ می‌شوند (state مفسر روی عامل). سقف زمان و خروجی
          هر دستور روی سرور اعمال می‌شود و همه‌ی اجراها در حسابرسی ثبت‌اند. این مفسر Sandbox
          نیست: دسترسی اجرا هم‌سطح حساب کاربری سرویس Agent است.
        </div>
      </div>

      <div className="terminal">
        <div className="terminal-meta">
          <span>Remote Python — {agentLabel || agentId}</span>
          <span>{session ? `session ${session.id}` : "بدون نشست"}</span>
        </div>
        <div className="terminal-out" ref={outRef as React.RefObject<HTMLDivElement>} style={{ maxHeight: 420 }}>
          {!session && !pollErr && (
            <div style={{ color: "#64719b" }}>برای شروع، نشست را بسازید. دستورهای این نشست بی‌وابستگی به نشست‌های دیگر اجرا می‌شوند.</div>
          )}
          {pollErr && <div style={{ color: "var(--danger)" }}>{pollErr}</div>}
          {commands.map((c) => (
            fmtOut(c).map((l, i) => (
              <div key={`${c.id}-${i}`} style={{ color: colorFor[l.kind], whiteSpace: "pre-wrap" }}>
                {l.text}
                {l.kind === "code" && (
                  <span style={{ float: "right" }}>
                    {c.duration_ms != null && `[${faNum(Math.round(c.duration_ms))}ms]`}
                    {c.truncated ? " ⚠ خروجی بریده شد" : ""}
                    <button
                      className="btn ghost sm"
                      style={{ padding: "0 6px", verticalAlign: "baseline" }}
                      title="لغو اجرای این دستور"
                      onClick={() => cancelCommand(c)}
                    ><IconX size={11} /></button>
                  </span>
                )}
              </div>
            ))
          ))}
          {hasRunning && (
            <div style={{ color: "#64719b", display: "flex", gap: 8, alignItems: "center" }}>
              <MiniSpinner /> در انتظار نتیجه از عامل…
            </div>
          )}
        </div>
        <div className="terminal-input-row">
          <span className="prompt">{session ? ">>>" : "—"}</span>
          <textarea
            className="terminal-input"
            ref={taRef}
            rows={1}
            placeholder={session ? "کد پایتون (Shift+Enter خط جدید)…" : "اول نشست را بسازید"}
            disabled={!session}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void execute();
              }
            }}
          />
          <button className="btn primary sm" disabled={!session || !code.trim()} onClick={() => void execute()}>
            اجرا
          </button>
        </div>
      </div>

      <div className="row wrap" style={{ gap: 8 }}>
        <button className="btn sm" disabled={commands.length === 0}
          onClick={() => navigator.clipboard?.writeText(allText)}>
          <IconCopy size={13} /> کپی خروجی
        </button>
        <button className="btn sm" onClick={() => setCommands([])} disabled={!session}>پاک‌کردن نمایش</button>
        <span className="small muted" style={{ marginInlineStart: "auto" }}>
          نشست‌های دیگران و سایر عامل‌ها جدا هستند؛ آخرین sync: {fmtTime(session?.last_active_at ?? null)}
        </span>
      </div>
    </div>
  );
}

export default RemoteConsole;
