/** AI Action Proposals — the observe-first boundary of autonomy.
 *
 * Every "do something" the smart engine suggests is recorded as OBSERVED and
 * does nothing by itself. Approving runs the investigation on the target
 * (real record, audited); rejecting keeps history. No other path exists.
 */

import { useCallback, useState } from "react";
import { api, ApiError } from "../lib/api";
import { usePolling } from "../lib/polling";
import { faNum, fmtAgo } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/ui";

/* ---- types ------------------------------------------------------------- */

interface ActionRow {
  action_id: string;
  kind: string;
  rationale: string | null;
  target?: { alert_id?: number; target_ip?: string; ref_alert_id?: number } | null;
  source: string;
  status: string;
  created_at: string | null;
  decided_by: string | null;
  decided_at: string | null;
  result?: { investigation_id?: number; error?: string } | null;
}

const STATUS: Record<string, { label: string; tone: string }> = {
  OBSERVED: { label: "مشاهده‌شده (در انتظار تصمیم شما)", tone: "badge-accent" },
  APPROVED: { label: "تأییدشده", tone: "badge-ok" },
  EXECUTED: { label: "اجرا شد", tone: "badge-ok" },
  REJECTED: { label: "ردشده", tone: "badge-muted" },
  FAILED: { label: "اجرا ناموفق", tone: "badge-danger" },
};

const KIND: Record<string, string> = {
  run_investigation: "اجرای بررسی هوشمند",
};

function targetText(t: ActionRow["target"]): string {
  if (!t) return "";
  return [
    t.target_ip ? `هدف: ${t.target_ip}` : "",
    t.alert_id !== undefined ? `هشدار #${faNum(t.alert_id)}` : "",
  ].filter(Boolean).join(" · ");
}

export default function AIActionsPage() {
  const [items, setItems] = useState<ActionRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(true);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      setError(null);
      const d = await api.get<{ items: ActionRow[] }>("/api/admin/v1/ai-actions?limit=100", { signal });
      if (signal?.aborted) return;
      setItems(d.items);
    } catch (e) {
      if (signal?.aborted) return;
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  usePolling(load, 7000, live, refreshKey);

  const decide = async (action_id: string, drop: "approve" | "reject") => {
    setBusy(true);
    setError(null);
    try {
      await api.post(`/api/admin/v1/ai-actions/${action_id}/${drop}`);
      setRefresh((k) => k + 1);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : "خطای ناشناخته");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <Card
        title="پیشنهادهای عملکرد هوشمند (Observe Only به‌صورت پیش‌فرض)"
        extra={
          <>
            <label className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
              به‌روزرسانی زنده (۷ ثانیه)
            </label>
            <button className="btn ghost sm" onClick={() => setRefresh((k) => k + 1)}>بارگیری مجدد</button>
          </>
        }
      >
        <div className="small muted">
          هوش مصنوعی هیچ کاری را به‌تنهایی انجام نمی‌دهد: تحلیل‌گر وقتی یافته‌ی
          پراهمیتی می‌بیند، فقط یک «پیشنهاد بررسی» ثبت می‌کند. اجرا فقط با دکمه‌ی
          تأیید شما رخ می‌دهد و در حسابرسی ثبت می‌شود.
        </div>
      </Card>

      <div style={{ height: 12 }} />

      {error && <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />}

      <Card title="همه‌ی پیشنهادها" extra={null}>
        {items === null && !error && <SkeletonRows rows={5} />}
        {items !== null && items.length === 0 && (
          <EmptyState
            title="پیشنهادی ثبت نشده است"
            hint="وقتی تحلیل هشدارها اهمیت بالا را گزارش کند، پیشنهاد بررسی اینجاست."
          />
        )}
        {items !== null && items.length > 0 && (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {items.map((a) => {
              const st = STATUS[a.status] ?? { label: a.status, tone: "badge-muted" };
              return (
                <li key={a.action_id} className="card" style={{ padding: "10px 14px", marginBottom: 8 }}>
                  <div className="row small" style={{ gap: 10, flexWrap: "wrap" }}>
                    <b>{KIND[a.kind] ?? a.kind}</b>
                    {targetText(a.target) && <span className="small technical muted">{targetText(a.target)}</span>}
                    <div className="spacer" />
                    <span className="small muted">{fmtAgo(a.created_at ?? "")}</span>
                    <span className={`badge ${st.tone}`}><span className="dot" />{st.label}</span>
                  </div>
                  {a.rationale && <div className="small muted" style={{ marginTop: 4 }}>{a.rationale}</div>}
                  {(a.result?.error || a.result?.investigation_id !== undefined) && (
                    <div className="small" style={{ marginTop: 4 }}>
                      {a.result?.error
                        ? <span style={{ color: "var(--danger)" }}>{a.result.error}</span>
                        : a.result?.investigation_id !== undefined && (
                          <>بررسی انجام‌شده: <b>#{faNum(a.result.investigation_id)}</b></>
                        )}
                    </div>
                  )}
                  {a.decided_by && (
                    <div className="small muted" style={{ marginTop: 4 }}>
                      تصمیم: {a.decided_by}
                    </div>
                  )}
                  {a.status === "OBSERVED" && (
                    <div className="row" style={{ gap: 8, marginTop: 8 }}>
                      <button className="btn sm" disabled={busy} onClick={() => void decide(a.action_id, "approve")}>
                        تأیید و اجرای بررسی
                      </button>
                      <button className="btn ghost sm" disabled={busy} onClick={() => void decide(a.action_id, "reject")}>
                        رد
                      </button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
