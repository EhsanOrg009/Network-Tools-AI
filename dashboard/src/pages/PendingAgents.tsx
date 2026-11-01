import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { EnrollmentRequest } from "../lib/types";
import { faNum, fmtDateTime, fmtAgo } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, StatusPill, TechChip } from "../components/ui";
import { useToast } from "../components/toast";
import { IconAlert, IconCheck, IconX } from "../components/icons";

/** Pending self-registration requests — the administrator's approval desk. */

export default function PendingAgentsPage() {
  const [items, setItems] = useState<EnrollmentRequest[] | null>(null);
  const [history, setHistory] = useState<EnrollmentRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<EnrollmentRequest | null>(null);
  const [confirm, setConfirm] = useState<{ req: EnrollmentRequest; reject: boolean } | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [refreshKey, setRefresh] = useState(0);
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      setError(null);
      const [pending, decided] = await Promise.all([
        api.get<{ items: EnrollmentRequest[] }>("/api/admin/v1/enrollment-requests?status=PENDING_APPROVAL&limit=200"),
        api.get<{ items: EnrollmentRequest[] }>("/api/admin/v1/enrollment-requests?limit=50"),
      ]);
      setItems(pending.items);
      setHistory(decided.items.filter((r) => r.status !== "PENDING_APPROVAL"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  async function decide(req: EnrollmentRequest, reject: boolean) {
    setBusy(true);
    try {
      const res = await api.post<EnrollmentRequest>(
        reject
          ? `/api/admin/v1/enrollment-requests/${req.id}/reject`
          : `/api/admin/v1/enrollment-requests/${req.id}/approve`,
        { reason: reason.trim() || undefined },
      );
      toast.push(
        reject ? `درخواست «${req.hostname ?? req.id}» رد شد.` : `درخواست «${req.hostname ?? req.id}» تأیید شد؛ عامل با polling ثبت‌نام را کامل می‌کند.`,
        "success",
      );
      setConfirm(null);
      setDetail(null);
      setReason("");
      void res;
      setRefresh((k) => k + 1);
    } catch (e) {
      toast.push(e instanceof Error ? `عملیات ناموفق: ${e.message}` : "عملیات ناموفق", "error");
    } finally {
      setBusy(false);
    }
  }

  const platform = (r: EnrollmentRequest): string => {
    const p = r.platform as { os_family?: string; os_name?: string; arch?: string } | null;
    return p ? `${p.os_name ?? p.os_family ?? "—"}${p.arch ? ` — ${p.arch}` : ""}` : "—";
  };

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row" style={{ gap: 12 }}>
          <IconAlert size={20} style={{ color: "var(--warn)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>دسکتاپ‌هایی که خودشان را معرفی کرده‌اند</div>
            <div className="small muted">
              اطلاعات این دستگاه‌ها «اعلامی» است و تا تأییدنشدن هیچ اعتباری ندارد. تأیید،
              اعتبارنامه‌ی اختصاصی صادر می‌کند که عامل در اولین polling تحویل می‌گیرد.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      <Card pad={false}>
        {items === null && !error ? (
          <SkeletonRows rows={4} />
        ) : error ? (
          <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
        ) : (items ?? []).length === 0 ? (
          <EmptyState title="درخواست در انتظار تأییدی نیست" hint="هنگام درخواست عامل‌های جدید، همین‌جا ظاهر می‌شوند." />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Hostname (اعلامی)</th>
                  <th>سیستم‌عامل (اعلامی)</th>
                  <th>MAC</th>
                  <th>Gateway</th>
                  <th>IPهای اعلامی</th>
                  <th>زمان درخواست</th>
                  <th>انقضا</th>
                  <th style={{ width: 190 }}></th>
                </tr>
              </thead>
              <tbody>
                {(items ?? []).map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => setDetail(r)}>
                    <td><div style={{ fontWeight: 600 }}>{r.hostname ?? "—"}</div><TechChip>{r.id}</TechChip></td>
                    <td>{platform(r)}</td>
                    <td className="technical small">{r.mac ?? "—"}</td>
                    <td className="technical small">{r.gateway ?? "—"}</td>
                    <td className="technical small">{(r.claimed_ips ?? []).slice(0, 2).join(" ، ") || "—"}</td>
                    <td title={fmtDateTime(r.requested_at)}>{fmtAgo(r.requested_at)}</td>
                    <td className="small muted">{fmtDateTime(r.expires_at)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="row" style={{ gap: 6 }}>
                        <button className="btn primary sm" onClick={() => setConfirm({ req: r, reject: false })}>
                          <IconCheck size={14} /> تأیید
                        </button>
                        <button className="btn danger sm" onClick={() => setConfirm({ req: r, reject: true })}>
                          <IconX size={14} /> رد
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {history !== null && history.length > 0 && (
        <Card pad={false} title="تاریخچه‌ی تصمیم‌های قبل" extra={<span className="badge badge-muted">{faNum(history.length)}</span>}>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>عامل/درخواست</th><th>وضعیت</th><th>دلیل رد</th><th>تصمیم‌گیرنده</th><th>زمان تصمیم</th></tr>
              </thead>
              <tbody>
                {history.map((r) => (
                  <tr key={r.id}>
                    <td className="technical small">{r.hostname ?? r.id}</td>
                    <td><StatusPill state={r.status} /></td>
                    <td className="small">{r.reject_reason ?? "—"}</td>
                    <td className="small">{r.reviewed_by ?? "—"}</td>
                    <td className="small muted">{fmtDateTime(r.reviewed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* detail drawer */}
      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: 10 }}>
              <h3 style={{ fontSize: 15 }}>جزئیات درخواست (اطلاعات اعلامی عامل)</h3>
              <div className="spacer" />
              <StatusPill state={detail.status} pulse />
            </div>
            <pre className="code-block" style={{ maxHeight: 320 }}>{JSON.stringify(detail, null, 2)}</pre>
            <div className="row" style={{ marginTop: 16, gap: 8 }}>
              <button className="btn primary" onClick={() => setConfirm({ req: detail, reject: false })}>
                <IconCheck size={14} /> تأیید ثبت‌نام
              </button>
              <button className="btn danger" onClick={() => setConfirm({ req: detail, reject: true })}>
                <IconX size={14} /> رد درخواست
              </button>
              <div className="spacer" />
              <button className="btn ghost" onClick={() => setDetail(null)}>بستن</button>
            </div>
          </div>
        </div>
      )}

      {/* confirm approve/reject */}
      <div className="modal-backdrop" style={{ display: confirm ? "grid" : "none" }} onClick={() => setConfirm(null)}>
        <div className="modal" onClick={(e) => e.stopPropagation()} hidden={!confirm}>
          {confirm && (
            <>
              <h3 style={{ fontSize: 15, marginBottom: 10 }}>
                {confirm.reject ? "رد درخواست ثبت‌نام" : "تأیید درخواست ثبت‌نام"}
              </h3>
              <div className="small" style={{ color: "var(--text-2)", lineHeight: 1.9 }}>
                {confirm.reject ? (
                  <>
                    دستگاه <b className="technical">{confirm.req.hostname ?? confirm.req.id}</b> تأیید
                    نمی‌شود و هرگز اعتبارنامه نمی‌گیرد؛ دلیل رد در سابقه می‌ماند و عامل آن را در
                    polling بعدی می‌بیند.
                  </>
                ) : (
                  <>
                    به دستگاه <b className="technical">{confirm.req.hostname ?? confirm.req.id}</b> یک
                    شناسه‌ی دائمی و اعتبارنامه‌ی اختصاصی صادر می‌شود. عامل در polling بعدی آن را
                    تحویل می‌گیرد و از این پس عضو سامانه است.
                  </>
                )}
              </div>
              {confirm.reject && (
                <div style={{ marginTop: 12 }}>
                  <label className="field-label" htmlFor="reject-reason">دلیل رد (اختیاری)</label>
                  <input
                    id="reject-reason"
                    className="input"
                    placeholder="مثلاً: دستگاه ناشناس است"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    maxLength={200}
                  />
                </div>
              )}
              <div className="row" style={{ marginTop: 18, gap: 8 }}>
                <button
                  className={`btn ${confirm.reject ? "danger" : "primary"}`}
                  disabled={busy}
                  onClick={() => decide(confirm.req, confirm.reject)}
                >
                  {busy ? "در حال انجام…" : confirm.reject ? "رد نهایی" : "تأیید نهایی"}
                </button>
                <button className="btn ghost" onClick={() => setConfirm(null)}>انصراف</button>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="small muted section-gap">
        درخواست‌های منقضی‌شده به‌صورت خودکار بسته می‌شوند؛ دستگاه می‌تواند بعد دوباره معرفی شود
        و رکورد تکراری نسازد.
      </div>
    </div>
  );
}

