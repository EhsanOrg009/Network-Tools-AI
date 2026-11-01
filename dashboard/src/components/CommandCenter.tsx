/**
 * Command Center: the operator's fast lane for everyday network operations.
 * Every action calls the real backend (`/api/tools/*`, `/api/hosts/discover`)
 * with the same scope validation as the CLI/agent; the sensitive one
 * (network discovery) asks for explicit confirmation showing tool + target.
 */

import { useCallback, useState } from "react";
import { api, ApiError } from "../lib/api";
import { faNum } from "../lib/format";
import { Card, EmptyState } from "./ui";
import { IconGauge } from "./icons";

type OpKind = "ping" | "tcp_check" | "discover" | "fingerprint";

interface OpResult {
  ok: boolean;
  title: string;
  body: string; // pretty JSON of the real response
}

const OP_TITLES: Record<OpKind, string> = {
  ping: "بررسی ICMP (ping)",
  tcp_check: "بررسی اتصال TCP",
  discover: "کشف میزبان در محدوده",
  fingerprint: "شناسایی کامل میزبان",
};

function errMsg(e: unknown): string {
  return e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته";
}

export function CommandCenter() {
  const [kind, setKind] = useState<OpKind>("ping");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("443");
  const [tool, setTool] = useState<"nmap" | "arp_scan">("nmap");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<OpResult | null>(null);

  const run = useCallback(async (op: OpKind, payload: Record<string, unknown>) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      if (op === "discover") {
        const d = await api.post<Record<string, unknown>>("/api/hosts/discover", payload);
        setResult({
          ok: d.ok === true,
          title: OP_TITLES[op],
          body: JSON.stringify(d, null, 2),
        });
      } else {
        const toolName = op === "fingerprint" ? "host_fingerprint" : op;
        const d = await api.post<Record<string, unknown>>(`/api/tools/${toolName}`, payload);
        setResult({ ok: d.ok === true, title: OP_TITLES[op], body: JSON.stringify(d, null, 2) });
      }
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }, []);

  const submit = useCallback(() => {
    const t = target.trim();
    if (!t) {
      setError("هدف را وارد کنید (IP یا CIDR).");
      return;
    }
    if (kind === "ping") return void run("ping", { host: t });
    if (kind === "tcp_check") {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        setError("پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.");
        return;
      }
      return void run("tcp_check", { host: t, port: p });
    }
    if (kind === "fingerprint") return void run("fingerprint", { target: t });
    // discover: sensitive → explicit confirmation first
    setConfirming(true);
  }, [kind, target, port, run]);

  return (
    <Card
      title={<><IconGauge size={16} /> Command Center — عملیات سریع مدیر</>}
      extra={<span className="small muted">همه‌ی عملیات با همان اعتبارسنجی scope سرور اجرا می‌شوند و ثبت می‌گردند</span>}
    >
      <div className="row wrap" style={{ gap: 10 }}>
        <select className="input" style={{ width: 190 }} value={kind}
          onChange={(e) => { setKind(e.target.value as OpKind); setError(null); setConfirming(false); }}>
          <option value="ping">بررسی اتصال (ping)</option>
          <option value="tcp_check">بررسی پورت TCP</option>
          <option value="discover">کشف میزبان در محدوده</option>
          <option value="fingerprint">شناسایی میزبان (fingerprint)</option>
        </select>
        <input
          className="input technical" style={{ width: 220 }} placeholder={kind === "discover" ? "192.168.1.0/24" : "192.168.1.10"}
          value={target} onChange={(e) => setTarget(e.target.value)}
        />
        {kind === "tcp_check" && (
          <input
            className="input technical" style={{ width: 90 }} placeholder="پورت"
            value={port} onChange={(e) => setPort(e.target.value)}
          />
        )}
        {kind === "discover" && (
          <select className="input" style={{ width: 130 }} value={tool} onChange={(e) => setTool(e.target.value as "nmap" | "arp_scan")}>
            <option value="nmap">nmap (-sn)</option>
            <option value="arp_scan">arp-scan</option>
          </select>
        )}
        <button className="btn" disabled={busy} onClick={submit}>
          {busy ? "…" : "اجرای عملیات"}
        </button>
      </div>

      {confirming && (
        <div className="card card-pad" style={{ marginTop: 12, background: "var(--bg-card-2)", border: "1px solid var(--warn, #e2a336)" }}>
          <div className="small">
            <b>تأیید عملیات حساس:</b> کشف میزبان با <span className="technical">{tool}</span> روی{" "}
            <span className="technical">{target.trim()}</span> اجرا می‌شود — فقط هدف داخل محدوده‌ی
            مجاز پذیرفته می‌شود و هدف خارج از scope با 403 رد خواهد شد.
          </div>
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button className="btn" disabled={busy}
              onClick={() => { void run("discover", { tool, target: target.trim() }); }}>
              تأیید و اجرا
            </button>
            <button className="btn ghost" onClick={() => setConfirming(false)}>انصراف</button>
          </div>
        </div>
      )}

      {error && <div className="small" style={{ color: "var(--danger)", marginTop: 10 }}>خطا: {error}</div>}

      {result && (
        <div style={{ marginTop: 12 }}>
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <span className={`badge ${result.ok ? "badge-ok" : "badge-warn"}`}>
              {result.ok ? "موفق" : "ناموفق/محدود"}
            </span>
            <b className="small">{result.title}</b>
          </div>
          <pre className="code-block" style={{ maxHeight: 280 }}>{result.body}</pre>
        </div>
      )}

      {!result && !error && !confirming && (
        <EmptyState title="عملیاتی اجرا نشده"
          hint="ping و tcp_check و fingerprint روی میزبان‌های مجاز؛ کشف فقط روی CIDR مجاز." />
      )}
      {result && (
        <div className="small muted" style={{ marginTop: 6 }}>
          خروجی خام همان پاسخ سرور است ({faNum(result.body.length)} بایت) — بدون واسطه‌سازی.
        </div>
      )}
    </Card>
  );
}

export default CommandCenter;
