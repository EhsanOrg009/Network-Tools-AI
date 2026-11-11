import type { ReactNode, ReactElement } from "react";
import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { stateLabel, faNum } from "../lib/format";
import { IconAlert, IconSearch, IconOff, IconRefresh, IconX } from "./icons";

/** Status pill with standard NOC color semantics. */
export function StatusPill({ state, pulse }: { state: string | null | undefined; pulse?: boolean }) {
  const { label, tone } = stateLabel(state);
  const cls = { ok: "badge-ok", warn: "badge-warn", danger: "badge-danger", muted: "badge-muted", accent: "badge-accent" }[tone];
  return (
    <span className={`badge ${cls}`}>
      <span className={`dot${pulse ? " pulse" : ""}`} />
      {label}
    </span>
  );
}

export function StatCard({ label, value, hint, icon, color = "var(--accent)" }: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  color?: string;
}) {
  return (
    <div className="card stat-card" style={{ ["--stat-color" as string]: color }}>
      <div className="stat-top">
        <div className="stat-label">{label}</div>
        {icon && <div className="stat-icon">{icon}</div>}
      </div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Card({ title, extra, children, pad = true, className, style }: {
  title?: ReactNode;
  extra?: ReactNode;
  children: ReactNode;
  pad?: boolean;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div className={`card${pad ? " card-pad" : ""}${className ? ` ${className}` : ""}`} style={style}>
      {(title || extra) && (
        <div className="card-header">
          <h3 className="card-title">{title}</h3>
          {extra && <div className="card-header-actions">{extra}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

/* ---- async states ------------------------------------------------------ */

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state-block">
      <IconAlert size={40} />
      <div>
        <div className="big">اطلاعات در دسترس نیست</div>
        <div className="small muted">{message}</div>
      </div>
      {onRetry && (
        <button className="btn" onClick={onRetry}><IconRefresh size={15} /> تلاش دوباره</button>
      )}
    </div>
  );
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactElement }) {
  return (
    <div className="state-block">
      <IconSearch size={40} />
      <div>
        <div className="big">{title}</div>
        {hint && <div className="small muted">{hint}</div>}
      </div>
      {action}
    </div>
  );
}

export function DisconnectedState({ onRetry }: { onRetry?: () => void }) {
  return (
    <div className="state-block">
      <IconOff size={40} />
      <div>
        <div className="big">ارتباط با هسته‌ی مرکزی قطع است</div>
        <div className="small muted">
          داده‌های نشان‌داده‌شده قدیمی‌اند؛ پس از برقراری ارتباط دوباره همگام می‌شود.
        </div>
      </div>
      {onRetry && (
        <button className="btn primary" onClick={onRetry}><IconRefresh size={15} /> اتصال دوباره</button>
      )}
    </div>
  );
}

export function Skeleton({ width = "100%", height = 16, style }: { width?: string | number; height?: number | string; style?: React.CSSProperties }) {
  return <span className="skeleton" style={{ display: "block", width, height, ...style }} />;
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <tbody>
          {Array.from({ length: rows }, (_, i) => (
            <tr key={i}>
              {[30, 22, 18, 26].map((w, c) => (
                <td key={c}><Skeleton width={`${w}%`} height={13} /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MiniSpinner() {
  return <span className="spinner" style={{ width: 15, height: 15, borderWidth: 2 }} />;
}

/* ---- modal ------------------------------------------------------------- */

export function Dialog({ title, children, onClose, wide = false, busy = false }: {
  title: string; children: ReactNode; onClose: () => void; wide?: boolean; busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => { dialog.close(); };
  }, []);
  return createPortal(
    <dialog ref={ref} className={`modal${wide ? " wide" : ""}`} aria-labelledby={id}
      onCancel={(e) => { e.preventDefault(); if (!busy) onClose(); }}
      onClick={(e) => {
        if (e.target !== e.currentTarget || busy) return;
        const rect = e.currentTarget.getBoundingClientRect();
        if (e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom) onClose();
      }}>
      <div className="modal-heading"><h2 id={id}>{title}</h2><button className="btn ghost icon-btn" aria-label="بستن پنجره" disabled={busy} onClick={onClose}><IconX size={17} /></button></div>
      {children}
    </dialog>, document.body,
  );
}

export function ConfirmDialog({ open, title, message, confirmLabel = "مطمئنم، ادامه", danger, busy, onConfirm, onCancel }: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (!open) return null;
  return (
    <Dialog title={title} onClose={onCancel} busy={busy}>
        <div className="small" style={{ color: "var(--text-2)", lineHeight: 1.9 }}>{message}</div>
        <div className="row" style={{ marginTop: 20, justifyContent: "flex-start", gap: 8 }}>
          <button className={`btn ${danger ? "danger" : "primary"}`} disabled={busy} onClick={onConfirm}>
            {busy ? <MiniSpinner /> : null}
            {confirmLabel}
          </button>
          <button className="btn ghost" disabled={busy} onClick={onCancel}>انصراف</button>
        </div>
    </Dialog>
  );
}

/** LTR technical value chip (IPs, MACs, ids). */
export function TechChip({ children, onCopy }: { children: string; onCopy?: boolean }) {
  return (
    <span
      className="code-chip"
      title={onCopy ? "برای کپی کلیک کنید" : undefined}
      style={onCopy ? { cursor: "copy" } : undefined}
      onClick={onCopy ? () => navigator.clipboard?.writeText(children) : undefined}
    >
      {children}
    </span>
  );
}

export function CountPill({ n, tone = "warn" }: { n: number; tone?: "warn" | "accent" | "danger" }) {
  const cls = { warn: "badge-warn", accent: "badge-accent", danger: "badge-danger" }[tone];
  return <span className={`badge ${cls}`}>{faNum(n)}</span>;
}
