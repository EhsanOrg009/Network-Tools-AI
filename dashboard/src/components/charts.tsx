/**
 * Hand-built SVG charts (no third-party chart lib): full styling control,
 * tiny bundle, RTL-friendly Persian labels.
 */

import type { ReactNode } from "react";
import { faNum, fmtDayShort } from "../lib/format";

export const CHART_COLORS = {
  accent: "var(--accent)",
  accent2: "var(--accent-2)",
  ok: "var(--ok)",
  warn: "var(--warn)",
  danger: "var(--danger)",
  muted: "var(--muted)",
  sev3: "var(--warn)",
  sev4: "#8aa1c8",
};

/** Horizontal bar list — severity breakdown, status breakdown, etc. */
export function BarList({ items, color = CHART_COLORS.accent, formatValue = faNum }: {
  items: { label: string; value: number; color?: string }[];
  color?: string;
  formatValue?: (n: number) => string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) {
    return <div className="small muted" style={{ padding: "8px 2px" }}>داده‌ای موجود نیست</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {items.map((it) => (
        <div key={it.label}>
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 12.5, color: "var(--text-2)" }}>{it.label}</span>
            <span style={{ fontSize: 12.5, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>
              {formatValue(it.value)}
            </span>
          </div>
          <div style={{ height: 8, borderRadius: 6, background: "var(--muted-soft)", overflow: "hidden" }}>
            <div style={{
              height: "100%", borderRadius: 6,
              width: `${Math.max(2, (it.value / max) * 100)}%`,
              background: it.color || color,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** Column/pair trend chart (7-day activity): grouped bars + hairline grid. */
export function TrendChart({ data, series }: {
  data: { date: string; [k: string]: number | string }[];
  series: { key: string; label: string; color: string }[];
}) {
  if (!data.length) return null;
  const W = 640, H = 190, PadX = 26, PadTop = 14, PadBottom = 26;
  const innerW = W - PadX * 2, innerH = H - PadTop - PadBottom;
  const max = Math.max(1, ...data.flatMap((d) => series.map((s) => Number(d[s.key]) || 0)));
  const ticks = [0, 0.5, 1].map((t) => max * t);
  const groupW = innerW / data.length;
  const barW = Math.min(14, (groupW - 8) / series.length);

  const y = (v: number) => PadTop + innerH - (v / max) * innerH;
  const groupX = (i: number) => PadX + i * groupW + groupW / 2;

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", direction: "ltr" }}>
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={PadX} x2={W - PadX} y1={y(t)} y2={y(t)} stroke="var(--grid-line)" strokeWidth={1} />
            <text x={W - PadX + 4} y={y(t) + 3} fontSize={9} fill="var(--text-3)" textAnchor="start">
              {faNum(t)}
            </text>
          </g>
        ))}
        {data.map((d, i) => (
          <g key={i}>
            {series.map((s, si) => {
              const v = Number(d[s.key]) || 0;
              const h = v > 0 ? Math.max(2, (v / max) * innerH) : 0;
              const x = groupX(i) - (series.length * barW) / 2 + si * barW;
              return h ? (
                <rect
                  key={s.key}
                  x={x}
                  y={y(v)}
                  width={barW - 2} height={h} rx={2.5}
                  fill={s.color}
                  opacity={0.9}
                >
                  <title>{`${s.label}: ${faNum(v)}`}</title>
                </rect>
              ) : null;
            })}
            <text x={groupX(i)} y={H - 8} fontSize={9.5} fill="var(--text-3)" textAnchor="middle">
              {fmtDayShort(String(d.date))}
            </text>
          </g>
        ))}
      </svg>
      <div className="chart-legend" style={{ marginTop: 6 }}>
        {series.map((s) => (
          <span key={s.key} className="key">
            <span className="swatch" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Donut breakdown for agent states / anything small. */
export function Donut({ slices, centerLabel, centerValue }: {
  slices: { label: string; value: number; color: string }[];
  centerLabel?: string;
  centerValue?: ReactNode;
}) {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const R = 54, C = 2 * Math.PI * R;
  let offset = 0;
  const angle = (v: number) => C * (v / Math.max(total, 1));
  return (
    <div className="row wrap" style={{ gap: 22, justifyContent: "center" }}>
      <svg viewBox="0 0 140 140" width={140} height={140}>
        <circle cx="70" cy="70" r={R} fill="none" stroke="var(--muted-soft)" strokeWidth={15} />
        {total > 0 && slices.map((s, i) => {
          const a = angle(s.value);
          if (s.value <= 0) return null;
          const el = (
            <circle
              key={i} cx="70" cy="70" r={R} fill="none"
              stroke={s.color} strokeWidth={15}
              strokeDasharray={`${a} ${C - a}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 70 70)"
              strokeLinecap="butt"
            />
          );
          offset += a;
          return el;
        })}
        <text x="70" y="66" textAnchor="middle" fontSize={22} fontWeight={800} fill="var(--text-1)">
          {centerValue}
        </text>
        <text x="70" y="86" textAnchor="middle" fontSize={10} fill="var(--text-3)">
          {centerLabel}
        </text>
      </svg>
      <div className="chart-legend" style={{ flexDirection: "column", gap: 8 }}>
        {slices.map((s) => (
          <span key={s.label} className="key">
            <span className="swatch" style={{ background: s.color }} />
            {s.label} — <b>{faNum(s.value)}</b>
          </span>
        ))}
      </div>
    </div>
  );
}
