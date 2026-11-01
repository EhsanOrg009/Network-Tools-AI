/** AI Investigations: LLM-driven host/alert investigations with reports. */

import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Investigation } from "../lib/types";
import { fmtAgo, fmtDateTime } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, StatusPill, TechChip } from "../components/ui";
import { IconBrain } from "../components/icons";

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
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
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

      <Card pad={false} title="فهرست بررسی‌ها">
        {items === null && !error ? <SkeletonRows rows={5} />
          : error ? <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
            : (items ?? []).length === 0 ? (
              <EmptyState title="بررسی‌ای انجام نشده"
                hint="برای شروع یک تحقیق، در صفحه‌ی میزبان‌های API یا از همان مرکز امنیت اقدام کنید." />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>موضوع</th><th>هدف</th><th>وضعیت</th><th>اطمینان</th><th>شروع / پایان</th></tr>
                  </thead>
                  <tbody>
                    {(items ?? []).map((inv) => (
                      <tr key={inv.id} className="clickable" onClick={() => setDetail(inv)}>
                        <td style={{ maxWidth: 300 }}>{inv.trigger} {inv.question ? <span className="small muted">— {inv.question.slice(0, 60)}</span> : null}</td>
                        <td><TechChip>{inv.target_ip ?? "—"}</TechChip></td>
                        <td><StatusPill state={inv.status} /></td>
                        <td className="small">{inv.confidence ?? "—"}</td>
                        <td className="small muted">{fmtAgo(inv.created_at)} → {inv.finished_at ? fmtAgo(inv.finished_at) : "در جریان"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
      </Card>

      {detail && (
        <div className="modal-backdrop" onClick={() => setDetail(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: 10, gap: 10 }}>
              <h3 style={{ fontSize: 15 }}>گزارش بررسی #{detail.id}</h3>
              <StatusPill state={detail.status} />
            </div>
            <dl className="two-col-defs small">
              <dt>هدف</dt><dd><TechChip>{detail.target_ip ?? "—"}</TechChip></dd>
              <dt>پرسش</dt><dd>{detail.question ?? "—"}</dd>
              <dt>شروع</dt><dd>{fmtDateTime(detail.created_at)}</dd>
              <dt>پایان</dt><dd>{fmtDateTime(detail.finished_at)}</dd>
              <dt>iterationها</dt><dd>{detail.iterations ?? "—"}</dd>
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
          </div>
        </div>
      )}
    </div>
  );
}
