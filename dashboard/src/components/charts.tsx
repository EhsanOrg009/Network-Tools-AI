/**
 * Hand-built SVG charts (no third-party chart lib): full styling control,
 * tiny bundle, RTL-friendly Persian labels.
 */

import type { ReactNode } from "react";
import { useState } from "react";
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
              width: `${(it.value / max) * 100}%`,
              background: it.color || color,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** Interactive chronological trend: straight lines retain actual measured values. */
export function TrendChart({ data, series }: {
  data: { date: string; [k: string]: number | string }[];
  series: { key: string; label: string; color: string }[];
}) {
  const [hidden, setHidden] = useState<string[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  if (!data.length) return <div className="state-block small">داده‌ای برای نمودار موجود نیست</div>;
  const W = 680, H = 224, left = 18, right = 54, top = 18, bottom = 38;
  const innerW = W - left - right, innerH = H - top - bottom;
  const visible = series.filter((s) => !hidden.includes(s.key));
  const rawMax = Math.max(1, ...data.flatMap((d) => visible.map((s) => Number(d[s.key]))));
  const magnitude = 10 ** Math.floor(Math.log10(rawMax));
  const step = Math.max(1, Math.ceil(rawMax / magnitude / 4) * magnitude);
  const max = Math.ceil(rawMax / step) * step;
  const x = (i: number) => left + innerW * i / Math.max(1, data.length - 1);
  const y = (v: number) => top + innerH - v / max * innerH;
  const index = Math.min(selected ?? data.length - 1, data.length - 1);
  const focus = data[index];
  return <div>
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", direction: "ltr", display: "block" }}
      role="img" aria-label="روند روزانهٔ رویدادها، هشدارها و عملیات مدیر">
      {[0, 1, 2, 3, 4].map((i) => {
        const value = max * i / 4;
        return <g key={i}><line x1={left} x2={W - right} y1={y(value)} y2={y(value)} stroke="var(--grid-line)" strokeDasharray="3 5" />
          <text x={W - right + 10} y={y(value) + 4} fill="var(--text-3)" fontSize="10">{faNum(Math.round(value))}</text></g>;
      })}
      {visible.map((s) => {
        const path = data.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i)} ${y(Number(d[s.key]))}`).join(" ");
        return <g key={s.key}>
          <path d={`${path} L ${x(data.length - 1)} ${y(0)} L ${x(0)} ${y(0)} Z`} fill={s.color} fillOpacity="0.05" />
          <path d={path} fill="none" stroke={s.color} strokeWidth="2.3" strokeLinejoin="round" />
          <circle cx={x(index)} cy={y(Number(focus[s.key]))} r="4" fill="var(--bg-card)" stroke={s.color} strokeWidth="2" />
        </g>;
      })}
      {data.map((d, i) => <g key={d.date} tabIndex={0} role="button" aria-label={`${fmtDayShort(String(d.date))}: ${series.map((s) => s.label + " " + faNum(Number(d[s.key]))).join("، ")}`}
        onFocus={() => setSelected(i)} onMouseEnter={() => setSelected(i)} onClick={() => setSelected(i)}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") setSelected(Math.min(data.length - 1, index + 1));
          if (e.key === "ArrowLeft") setSelected(Math.max(0, index - 1));
        }}>
        <rect x={x(i) - innerW / Math.max(2, data.length) / 2} y={top} width={innerW / Math.max(1, data.length)} height={innerH} fill="transparent" />
        <text x={x(i)} y={H - 12} textAnchor="middle" fontSize="10" fill={i === index ? "var(--text-1)" : "var(--text-3)"}>{fmtDayShort(String(d.date))}</text>
      </g>)}
    </svg>
    <div className="chart-legend" style={{ marginTop: 12, alignItems: "center" }}>
      <span className="small muted">{fmtDayShort(String(focus.date))}</span>
      {series.map((s) => <button type="button" key={s.key} className="btn ghost sm"
        aria-pressed={!hidden.includes(s.key)} title="نمایش یا پنهان‌کردن این سری"
        style={{ opacity: hidden.includes(s.key) ? 0.5 : 1 }}
        onClick={() => setHidden((h) => h.includes(s.key) ? h.filter((k) => k !== s.key) : [...h, s.key])}>
        <span className="swatch" style={{ background: s.color }} />{s.label}<b>{faNum(Number(focus[s.key]))}</b>
      </button>)}
    </div>
  </div>;
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
      <div style={{ textAlign: "center" }}><svg viewBox="0 0 140 140" width={148} height={148} role="img" aria-label="تفکیک وضعیت عامل‌های ثبت‌شده">
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
        <text x="70" y="79" textAnchor="middle" fontSize={28} fontWeight={600} fill="var(--text-1)">
          {centerValue}
        </text>

      </svg><div className="small muted" style={{ maxWidth: 180 }}>{centerLabel}</div></div>
      <div className="chart-legend" style={{ flexDirection: "column", gap: 12 }}>
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
