import { useCallback, useId, useState } from "react";
import { api } from "../lib/api";
import { usePolling } from "../lib/polling";
import { faNum, fmtDateTime } from "../lib/format";
import { EmptyState, ErrorState, SkeletonRows } from "./ui";

interface ArchivedAnalysis {
  alert_id: number;
  job_id: string;
  status: "COMPLETED" | "FAILED";
  summary: string | null;
  error: string | null;
  recommendation: string | null;
  evidence: string[] | null;
  model: string | null;
  analyzed_at: string | null;
}

export default function AnalysisHistory({ alertId, jobId }: { alertId: number; jobId?: string }) {
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<{ items: ArchivedAnalysis[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const panelId = useId();
  const size = 20;
  const load = useCallback(async (signal: AbortSignal) => {
    if (!open) return;
    setError(null);
    setData(null);
    try {
      const response = await api.get<{ items: ArchivedAnalysis[]; total: number }>(
        `/api/admin/v1/ai-analyses/${alertId}/history?limit=${size}&offset=${page * size}`, { signal },
      );
      if (signal.aborted) return;
      if (!Array.isArray(response.items) || !Number.isInteger(response.total) || response.total < 0
          || response.items.some((item) => item.alert_id !== alertId)) throw new Error("پاسخ تاریخچهٔ این هشدار معتبر نیست.");
      setData(response);
    } catch (e) {
      if (!signal.aborted) setError(e instanceof Error ? e.message : "دریافت تاریخچه ناموفق بود.");
    }
  }, [alertId, open, page, jobId]);
  usePolling(load, 0, false, refresh);

  return <section className="analysis-history">
    <button className="btn ghost history-trigger" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((value) => !value)}>
      <span>تاریخچهٔ تلاش‌های قبلی</span><span aria-hidden="true">{open ? "−" : "+"}</span>
    </button>
    {open && <div id={panelId} className="history-panel">
      <p className="small muted">نتیجهٔ هر تلاش به همین هشدار تعلق دارد؛ بازکردن تاریخچه فقط آن را نمایش می‌دهد.</p>
      {error ? <ErrorState message={error} onRetry={() => setRefresh((value) => value + 1)} />
        : !data ? <SkeletonRows rows={2} />
          : data.items.length === 0 ? <EmptyState title="تلاش قبلی ثبت نشده" hint="پس از تلاش دوباره یا تحلیل مجدد، نتیجهٔ پیشین اینجا محفوظ می‌ماند." />
            : <div className="history-list">{data.items.map((item) => <article key={item.job_id} className="history-entry">
              <div className="row wrap">
                <span className={`badge ${item.status === "COMPLETED" ? "badge-ok" : "badge-danger"}`}>{item.status === "COMPLETED" ? "تکمیل‌شده" : "ناموفق"}</span>
                <time className="small muted">{fmtDateTime(item.analyzed_at)}</time>
                {item.model && <bdi className="small technical muted">{item.model}</bdi>}
              </div>
              {item.summary && <p>{item.summary}</p>}
              {item.error && <p className="history-error">خطا: <bdi>{item.error}</bdi></p>}
              {(item.evidence?.length || item.recommendation) && <details className="small">
                <summary>شواهد و پیشنهاد این تلاش</summary>
                {item.evidence?.map((evidence, index) => <p key={index}>{evidence}</p>)}
                {item.recommendation && <p>{item.recommendation}</p>}
              </details>}
              <bdi className="technical small muted">{item.job_id}</bdi>
            </article>)}</div>}
      {data && data.total > size && <div className="pagination row wrap">
        <span className="small muted">صفحهٔ {faNum(page + 1)} از {faNum(Math.ceil(data.total / size))}</span>
        <div className="spacer" />
        <button className="btn sm" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>تاریخچهٔ جدیدتر</button>
        <button className="btn sm" disabled={(page + 1) * size >= data.total} onClick={() => setPage((value) => value + 1)}>تاریخچهٔ قدیمی‌تر</button>
      </div>}
    </div>}
  </section>;
}
