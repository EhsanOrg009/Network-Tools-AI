/**
 * Traffic Monitoring for one endpoint — data source: the agent's own
 * periodic reports (`POST /api/agent/v1/traffic`), host-local metadata only
 * (interface counters + active connections; never payloads, never other
 * hosts' traffic).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { faNum, fmtDateTime } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows } from "./ui";
import { TrendChart, CHART_COLORS } from "./charts";

export interface TrafficSample {
  ts: string;
  epoch: number;
  interface: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_rate: number | null;
  tx_rate: number | null;
  active_connections: number | null;
  connections?: { local: string; remote: string; state: string | null }[] | null;
}

export interface TrafficBundle {
  samples: TrafficSample[];
  latest: TrafficSample | null;
  hours: number;
}

function fmtRate(kbps: number): string {
  if (kbps >= 1024 * 1024) return `${(kbps / 1024 / 1024).toFixed(1)} GB/s`;
  if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} MB/s`;
  return `${faNum(Math.round(kbps))} KB/s`;
}

export default function TrafficMonitor({ agentId }: { agentId: string }) {
  const [data, setData] = useState<TrafficBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hours, setHours] = useState(24);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const d = await api.get<TrafficBundle>(`/api/admin/v1/agents/${agentId}/traffic?hours=${hours}`);
      setData(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, [agentId, hours]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const interfaces = useMemo(() => {
    const set = new Set<string>();
    for (const s of data?.samples ?? []) set.add(s.interface);
    return [...set];
  }, [data]);

  const [iface, setIface] = useState<string>("all");
  const chartData = useMemo(() => {
    const rows = (data?.samples ?? []).filter((s) => iface === "all" || s.interface === iface);
    // group by timestamp so multiple interfaces share one x-axis point
    const byTs = new Map<string, { date: string; rx: number; tx: number }>();
    for (const s of rows) {
      const t = new Date(s.ts);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
      const entry = byTs.get(s.ts) ?? { date: label, rx: 0, tx: 0 };
      entry.rx += s.rx_rate ?? 0;
      entry.tx += s.tx_rate ?? 0;
      byTs.set(s.ts, entry);
    }
    return [...byTs.values()];
  }, [data, iface]);

  const latestConns = useMemo(() => {
    if (iface !== "all") return data?.latest?.connections ?? [];
    return data?.latest?.connections ?? [];
  }, [data, iface]);

  const lastAt = data?.latest?.ts ?? null;

  return (
    <div>
      <div className="grid-half" style={{ marginBottom: 14 }}>
        <Card
          title="نرخ Upload / Download — منبع: شمارنده‌های خود عامل"
          extra={
            <div className="row" style={{ gap: 8 }}>
              <select className="input" style={{ width: 110 }} value={hours}
                onChange={(e) => setHours(Number(e.target.value))}>
                <option value={1}>۱ ساعت</option>
                <option value={6}>۶ ساعت</option>
                <option value={24}>۲۴ ساعت</option>
                <option value={168}>۷ روز</option>
              </select>
              {interfaces.length > 1 && (
                <select className="input" style={{ width: 130 }} value={iface}
                  onChange={(e) => setIface(e.target.value)}>
                  <option value="all">همه‌ی رابط‌ها</option>
                  {interfaces.map((i) => <option key={i} value={i}>{i}</option>)}
                </select>
              )}
              <button className="btn sm" onClick={() => setRefresh((k) => k + 1)}>↻</button>
            </div>
          }
        >
          {error ? <ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} />
            : data === null ? <SkeletonRows rows={4} />
              : chartData.length < 2 ? (
                <EmptyState
                  title="داده‌ی کافی برای نمودار نیست"
                  hint="عامل باید با پرچم --enable-traffic اجرا شود و چند نمونه بفرستد (نرخ از اختلاف دو نمونه‌ی متوالی ساخته می‌شود)."
                />
              ) : (
                <>
                  <TrendChart
                    data={chartData}
                    series={[
                      { key: "rx", label: "Download", color: CHART_COLORS.accent },
                      { key: "tx", label: "Upload", color: CHART_COLORS.accent2 },
                    ]}
                  />
                  <div className="small muted" style={{ marginTop: 8 }}>
                    آخرین جمع‌آوری: {lastAt ? fmtDateTime(lastAt) : "—"}
                    {data.latest?.rx_rate != null && <> · آخرین نرخ: ↓{fmtRate(data.latest.rx_rate)} ↑{fmtRate(data.latest.tx_rate ?? 0)}</>}
                  </div>
                </>
              )}
        </Card>

        <Card title="پرونده‌ی نمونه‌ها (خام)" pad={false}>
          {data === null ? <SkeletonRows rows={4} />
            : (data.samples ?? []).length === 0 ? (
              <EmptyState title="نمونه‌ای ثبت نشده"
                hint="عامل بدون --enable-traffic داده‌ی ترافیک نمی‌فرستد." />
            ) : (
              <div className="table-wrap" style={{ maxHeight: 300 }}>
                <table className="data">
                  <thead>
                    <tr><th>زمان</th><th>رابط</th><th>↓ نرخ</th><th>↑ نرخ</th><th>اتصال‌ها</th></tr>
                  </thead>
                  <tbody>
                    {[...(data.samples ?? [])].reverse().slice(0, 40).map((s, i) => (
                      <tr key={`${s.ts}-${s.interface}-${i}`}>
                        <td className="small muted">{fmtDateTime(s.ts)}</td>
                        <td className="small technical">{s.interface}</td>
                        <td className="small">{s.rx_rate != null ? fmtRate(s.rx_rate) : "—"}</td>
                        <td className="small">{s.tx_rate != null ? fmtRate(s.tx_rate) : "—"}</td>
                        <td className="small">{s.active_connections != null ? faNum(s.active_connections) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </Card>
      </div>

      <Card pad={false} title="اتصال‌های فعال در آخرین گزارش (متادیتا؛ بدون محتوا)">
        {!latestConns || latestConns.length === 0 ? (
          <EmptyState title="اتصال فعالی گزارش نشده"
            hint="فقط اتصال‌های TCP خودِ سیستم عامل در لحظه‌ی جمع‌آوری؛ بدون نام پروسه." />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>مبدأ محلی</th><th>مقصد</th><th>وضعیت</th></tr></thead>
              <tbody>
                {latestConns.slice(0, 50).map((c, i) => (
                  <tr key={i}>
                    <td className="technical small">{c.local}</td>
                    <td className="technical small">{c.remote}</td>
                    <td className="small">{c.state ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="small muted" style={{ margin: "10px 14px 12px" }}>
          حریم خصوصی: فقط متادیتای ترافیک سیستمِ خود عامل جمع‌آوری می‌شود — بدون payload،
          بدون نام پروسه، بدون ترافیک سایر دستگاه‌ها.
        </div>
      </Card>
    </div>
  );
}
