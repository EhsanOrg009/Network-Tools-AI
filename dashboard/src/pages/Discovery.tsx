/**
 * Network discovery page.
 *
 * Three concepts, deliberately kept separate (never merged):
 *  - Observed:  what agents actually reported (`observations`)
 *  - Configured: what the operator defined (`effective_scope.configured_cidrs`
 *    + `authorized_targets`)
 *  - Authorized for active discovery: policy verdict (`auto_discovered` +
 *    `auto_discovery_enabled`) — observing a network never implies it may be
 *    scanned.
 *
 * Topology edges are drawn only from real containment checks (ipaddr.js),
 * never from string prefixes.
 */

import { useCallback, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import { usePolling } from "../lib/polling";
import { ipInCidr, isValidCidr } from "../lib/cidr";
import { parseNetworksResponse } from "../lib/validate";
import type { AgentSummary, EffectiveDiscoveryScope, HostRow, NetworkObservationRow } from "../lib/types";
import { faNum, fmtAgo } from "../lib/format";
import { Card, EmptyState, ErrorState, SkeletonRows, TechChip } from "../components/ui";
import { IconWifi } from "../components/icons";

interface Loaded {
  observations: NetworkObservationRow[];
  scope: EffectiveDiscoveryScope;
}

export default function DiscoveryPage() {
  const [data, setData] = useState<Loaded | null>(null);
  const [hosts, setHosts] = useState<HostRow[] | null>(null);
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefresh] = useState(0);

  const load = useCallback(async (signal: AbortSignal) => {
    setError(null);
    try {
      const [net, h, a] = await Promise.all([
        api.get<unknown>("/api/admin/v1/networks?limit=200", { signal }),
        api.get<{ items: HostRow[] }>("/api/hosts?limit=200", { signal }),
        api.get<{ items: AgentSummary[] }>("/api/admin/v1/agents?limit=200", { signal }),
      ]);
      if (signal.aborted) return;
      const parsed = parseNetworksResponse(net); // throws on shape mismatch
      if (!Array.isArray(h.items) || !Array.isArray(a.items)) throw new Error("پاسخ میزبان‌ها یا عامل‌ها معتبر نیست.");
      setData({ observations: parsed.observations, scope: parsed.effective_scope });
      setHosts(h.items);
      setAgents(a.items);
    } catch (e) {
      if (signal.aborted) return;
      setError(
        e instanceof ApiError ? e.detail
        : e instanceof Error ? e.message
        : "خطای ناشناخته",
      );
    }
  }, []);

  usePolling(load, 0, false, refreshKey);

  const filteredHosts = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const list = hosts ?? [];
    if (!needle) return list;
    return list.filter((h) =>
      (h.ip ?? "").includes(needle)
      || (h.hostname ?? "").toLowerCase().includes(needle)
      || (h.mac ?? "").toLowerCase().includes(needle));
  }, [hosts, q]);

  /** Aggregated subnets from agent observations (dedup by cidr, keep latest
   *  seen + reporting agents) — pure frontend aggregation of real rows. */
  const observedSubnets = useMemo(() => {
    const byCidr = new Map<string, { cidr: string; agents: Set<string>; interfaces: Set<string>; last_seen: string; classification: string | null; connected: boolean }>();
    for (const o of data?.observations ?? []) {
      const cidr = (o.cidr ?? "").trim();
      if (!cidr || !isValidCidr(cidr)) continue;
      const cur = byCidr.get(cidr);
      if (cur) {
        cur.agents.add(o.agent_id);
        cur.interfaces.add(o.interface);
        if ((o.last_seen ?? "") > cur.last_seen) cur.last_seen = o.last_seen ?? "";
        if (o.connected === 1) cur.connected = true;
      } else {
        byCidr.set(cidr, {
          cidr,
          agents: new Set([o.agent_id]),
          interfaces: new Set([o.interface]),
          last_seen: o.last_seen ?? "",
          classification: o.classification ?? null,
          connected: o.connected === 1,
        });
      }
    }
    return [...byCidr.values()].sort((a, b) => b.last_seen.localeCompare(a.last_seen));
  }, [data]);

  /** Hosts per subnet via real CIDR containment (IPv4 + IPv6). */
  const topology = useMemo(() => {
    return observedSubnets.slice(0, 6).map((subnet) => {
      const inside = filteredHosts.filter((h) => ipInCidr(h.ip, subnet.cidr));
      return { subnet, hosts: inside.slice(0, 8), extra: Math.max(0, inside.length - 8) };
    });
  }, [observedSubnets, filteredHosts, agents]);

  const authorizedSet = useMemo(() => {
    const s = new Set<string>();
    for (const c of data?.scope.configured_cidrs ?? []) s.add(c);
    for (const a of data?.scope.auto_discovered ?? []) s.add(a.cidr);
    for (const t of data?.scope.authorized_targets ?? []) s.add(t);
    return s;
  }, [data]);

  return (
    <div>
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <IconWifi size={20} style={{ color: "var(--accent)" }} />
          <div>
            <div style={{ fontWeight: 700 }}>کشف شبکه — مشاهده‌شده، پیکربندی‌شده، مجاز</div>
            <div className="small muted">
              این سه مفهوم عمداً جدا هستند: مشاهده‌شدن یک شبکه به معنای مجاز بودن اسکن آن نیست.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={() => setRefresh((k) => k + 1)}>↻ به‌روزرسانی</button>
        </div>
      </div>

      {error ? (
        <div className="card"><ErrorState message={error} onRetry={() => setRefresh((k) => k + 1)} /></div>
      ) : !data ? (
        <div className="card card-pad"><SkeletonRows rows={5} /></div>
      ) : (
        <>
          {/* -- policy panel: Configured vs Authorized ------------------- */}
          <div className="grid-half" style={{ marginBottom: 14 }}>
            <Card title="محدوده‌ی پیکربندی‌شده (Configured)">
              {(data.scope.configured_cidrs.length === 0 && data.scope.authorized_targets.length === 0) ? (
                <EmptyState title="محدوده‌ای پیکربندی نشده"
                  hint="MONITOR_CIDRS / AUTHORIZED_TARGETS در تنظیمات سرور تعیین می‌شود." />
              ) : (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {data.scope.configured_cidrs.map((c) => (
                    <span key={c} className="badge badge-accent"><span className="technical">{c}</span></span>
                  ))}
                  {data.scope.authorized_targets.map((t) => (
                    <span key={t} className="badge badge-muted"><span className="technical">{t}</span></span>
                  ))}
                </div>
              )}
            </Card>
            <Card title="مجاز برای کشف فعال (Authorized — سیاست)">
              {!data.scope.auto_discovery_enabled && (data.scope.auto_discovered ?? []).length === 0 ? (
                <EmptyState title="کشف خودکار غیرفعال است"
                  hint="فقط محدوده‌ی پیکربندی‌شده برای اسکن فعال مجاز است." />
              ) : (
                <div>
                  <div className="small" style={{ marginBottom: 8 }}>
                    کشف خودکار: <b>{data.scope.auto_discovery_enabled ? "فعال" : "غیرفعال"}</b>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {(data.scope.auto_discovered ?? []).map((a) => (
                      <span key={a.cidr} className="badge badge-ok" title={a.justification}>
                        <span className="technical">{a.cidr}</span>
                        <span className="small muted"> ({faNum(a.reporting_agents?.length ?? 0)} عامل)</span>
                      </span>
                    ))}
                  </div>
                  <div className="small muted" style={{ marginTop: 8 }}>
                    فقط شبکه‌های خصوصیِ مستقیماً متصل با گزارش‌گر کافی — عمومی/VPN/loopback هرگز خودکار مجاز نمی‌شوند.
                  </div>
                </div>
              )}
            </Card>
          </div>

          {/* -- observed subnets ----------------------------------------- */}
          <div className="grid-half" style={{ marginBottom: 14 }}>
            <Card title="شبکه‌های مشاهده‌شده توسط عامل‌ها (Observed)" pad={false}>
              {observedSubnets.length === 0 ? (
                <EmptyState title="شبکه‌ای ثبت نشده"
                  hint="پس از inventory یا تسک network_configuration این‌جا می‌آید." />
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr><th>Subnet</th><th>عامل گزارش‌ده</th><th>رابط</th><th>طبقه‌بندی</th><th>آخرین مشاهده</th><th>مجاز؟</th></tr>
                    </thead>
                    <tbody>
                      {observedSubnets.map((n) => (
                        <tr key={n.cidr}>
                          <td><TechChip>{n.cidr}</TechChip></td>
                          <td>{faNum(n.agents.size)}</td>
                          <td className="small">{[...n.interfaces].join("، ")}</td>
                          <td className="small muted">{n.classification ?? "—"}</td>
                          <td className="small muted">{fmtAgo(n.last_seen)}</td>
                          <td>
                            {authorizedSet.has(n.cidr)
                              ? <span className="badge badge-ok">مجاز</span>
                              : <span className="badge badge-muted">فقط مشاهده</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>

            <Card title="توپولوژی مشاهده‌شده (لینک‌ها = داده‌ی واقعی)">
              {topology.length === 0 ? (
                <EmptyState title="داده‌ای برای ترسیم نیست" />
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  {topology.map(({ subnet, hosts: hs, extra }) => (
                    <div key={subnet.cidr} className="card" style={{ padding: 12, background: "var(--bg-card-2)" }}>
                      <div className="row">
                        <span className="badge badge-accent technical">{subnet.cidr}</span>
                        <span className="small muted">رابط: {[...subnet.interfaces].join("، ")}</span>
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                        {hs.map((h) => {
                          const isAgent = (agents ?? []).some((a) => a.status === "active" && (a.claimed_ips ?? []).includes(h.ip));
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
                        میزبان‌ها با تطبیق CIDR واقعی (IPv4/IPv6) پیدا شده‌اند؛ سبز = عامل فعال، خاکستری = بدون عامل.
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          {/* -- hosts ------------------------------------------------------ */}
          <Card pad={false} title="میزبان‌های شناسایی‌شده" extra={
            <input className="input" style={{ width: 220 }} placeholder="جست‌وجوی IP/MAC/نام…" value={q} onChange={(e) => setQ(e.target.value)} />
          }>
            {hosts === null ? <SkeletonRows rows={5} /> : filteredHosts.length === 0 ? (
              <EmptyState title="میزبانی ثبت نشده" hint="کشف شبکه فقط روی محدوده‌ی مجاز انجام می‌شود." />
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>اولین مشاهده</th><th>آخرین مشاهده</th><th>پوشش عامل</th></tr>
                  </thead>
                  <tbody>
                    {filteredHosts.slice(0, 100).map((h) => {
                      const isAgent = (agents ?? []).some((a) => a.status === "active" && (a.claimed_ips ?? []).includes(h.ip));
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
                              : <span className="badge badge-warn">بدون عامل</span>}
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
