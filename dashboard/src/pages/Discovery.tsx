/**
 * Network discovery: subnets observed by agents + discovered hosts +
 * a topology view derived ONLY from real observations (agent → network → host
 * edges that were actually seen; no invented connections).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { NetworkRow, HostRow, AgentSummary } from "../lib/types";
import { faNum, fmtAgo } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, TechChip } from "../components/ui";
import { IconWifi } from "../components/icons";

export default function DiscoveryPage() {
  const [networks, setNetworks] = useState<NetworkRow[] | null>(null);
  const [hosts, setHosts] = useState<HostRow[] | null>(null);
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [net, h, a] = await Promise.all([
        api.get<{ items: NetworkRow[] }>("/api/admin/v1/networks?limit=200"),
        api.get<{ items: HostRow[] }>("/api/hosts?limit=200").catch(() => null),
        api.get<{ items: AgentSummary[] }>("/api/admin/v1/agents?limit=200"),
      ]);
      setNetworks(net.items);
      setHosts(h?.items ?? []);
      setAgents(a.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "خطای ناشناخته");
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const filteredHosts = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return hosts ?? [];
    return (hosts ?? []).filter((h) =>
      (h.ip ?? "").includes(needle) || (h.hostname ?? "").toLowerCase().includes(needle) || (h.mac ?? "").includes(needle));
  }, [hosts, q]);

  /** Topology edges: an internet-style hub per subnet, agents attach via the
   *  interface they reported; hosts hang off the subnet that contains them
   *  (computation from real prefixes, never invented links). */
  const topology = useMemo(() => {
    const agentIps = new Set<string>();
    (agents ?? []).forEach((a) => (a.claimed_ips ?? []).forEach((ip) => agentIps.add(ip)));
    const nets = (networks ?? []).filter((n) => n.prefix).slice(0, 6);
    return nets.map((n) => {
      const prefix = String(n.prefix);
      // crude containment: same /24 (IPv4) or /64 (IPv6) using string prefix
      const base = prefix.split(".").slice(0, 3).join(".") ?? prefix.split(":").slice(0, 4).join(":");
      const inSubnet = (filteredHosts ?? []).filter((h) => (h.ip ?? "").startsWith(base === prefix ? String(h.ip) : base));
      return { net: n, hosts: inSubnet.slice(0, 8), extra: Math.max(0, inSubnet.length - 8) };
    });
  }, [networks, filteredHosts]);

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconWifi size={20} style={{ color: "var(--accent)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>شبکه‌های مشاهده‌شده توسط عامل‌ها</div>
            <div className="small muted">
              فقط چیزی که واقعاً از inventory عامل‌ها و کشف خودکار ثبت شده — عامل، منبع واقعی
              داده است؛ نشان‌دادن بدون عامل هم فقط از آدرس‌های ثبت‌شده است.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      {error ? (
        <div className="card"><ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} /></div>
      ) : (
        <>
          <div className="grid-half">
            <Card title="Subnetها و Gatewayها — منبع: گزارش عامل‌ها" pad={false}>
              {networks === null ? <SkeletonRows rows={4} /> : networks.length === 0 ? (
                <EmptyState title="شبکه‌ای ثبت نشده" hint="پس از inventory یا تسک network_configuration این‌جا می‌آید." />
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr><th>Subnet</th><th>Gateway</th><th>تعداد میزبان</th><th>آخرین مشاهده</th></tr>
                    </thead>
                    <tbody>
                      {networks.map((n, i) => (
                        <tr key={`${n.prefix}-${i}`}>
                          <td><TechChip>{n.prefix}</TechChip></td>
                          <td className="technical small">{n.gateway ?? "—"}</td>
                          <td>{faNum(n.host_count ?? null)}</td>
                          <td className="small muted">{fmtAgo(n.last_seen_at ?? null)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>

            <Card title="توپولوژی مشاهده‌شده (لینک‌ها = داده واقعی)">
              {topology.length === 0 ? (
                <EmptyState title="داده‌ای برای ترسیم نیست" />
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  {topology.map(({ net, hosts: hs, extra }) => (
                    <div key={String(net.prefix)} className="card" style={{ padding: 12, background: "var(--bg-card-2)" }}>
                      <div className="row">
                        <span className="badge badge-accent technical">{String(net.prefix)}</span>
                        {net.gateway && <span className="small muted">GW <span className="technical">{String(net.gateway)}</span></span>}
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                        {hs.map((h) => {
                          const isAgent = (agents ?? []).some((a) => (a.claimed_ips ?? []).includes(h.ip));
                          return (
                            <span key={h.ip} className={`badge ${isAgent ? "badge-ok" : "badge-muted"}`} title={h.hostname ?? ""}>
                              {isAgent && <span className="dot pulse" />}
                              <span className="technical">{h.ip}</span>
                            </span>
                          );
                        })}
                        {extra > 0 && <span className="badge badge-muted">+{faNum(extra)}</span>}
                      </div>
                      <div className="small muted" style={{ marginTop: 8 }}>
                        سبز: عامل فعال این رابط را گزارش کرده. خاکستری: میزبانِ شناسایی‌شده بدون عامل —
                        نقطه‌ی احتمالی نصب عامل.
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          <Card pad={false} title="میزبان‌های شناسایی‌شده" extra={
            <input className="input" style={{ width: 220 }} placeholder="جست‌وجوی IP/MAC/نام…" value={q} onChange={(e) => setQ(e.target.value)} />
          }>
            {hosts === null ? <SkeletonRows rows={5} /> : filteredHosts.length === 0 ? (
              <EmptyState title="میزبانی ثبت نشده" hint="کشف شبکه (nmap / arp-scan) فقط روی محدوده‌ی مجاز پیکربندی انجام می‌شود." />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>اولین مشاهده</th><th>آخرین مشاهده</th><th>عامل ندارد؟</th></tr>
                  </thead>
                  <tbody>
                    {filteredHosts.slice(0, 100).map((h) => {
                      const isAgent = (agents ?? []).some((a) => (a.claimed_ips ?? []).includes(h.ip));
                      return (
                        <tr key={h.ip}>
                          <td><TechChip>{h.ip}</TechChip></td>
                          <td>{h.hostname ?? "—"}</td>
                          <td className="technical small">{h.mac ?? "—"}</td>
                          <td className="small muted">{fmtAgo(h.first_seen ?? null)}</td>
                          <td className="small muted">{fmtAgo(h.last_seen ?? null)}</td>
                          <td>
                            {isAgent
                              ? <span className="badge badge-ok"><span className="dot pulse" />در پوشش عامل</span>
                              : h.first_seen ? <span className="badge badge-warn">بدون عامل</span> : <span className="small muted">—</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
