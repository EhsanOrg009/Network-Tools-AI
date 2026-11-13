/** Persian formatting helpers: Asia/Tehran dates, smart numbers, durations. */

const TEHRAN = "Asia/Tehran";

const tehranDT = new Intl.DateTimeFormat("fa-IR-u-ca-persian", {
  timeZone: TEHRAN,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const tehranTime = new Intl.DateTimeFormat("fa-IR", {
  timeZone: TEHRAN,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const tehranDay = new Intl.DateTimeFormat("fa-IR", {
  timeZone: TEHRAN,
  month: "short",
  day: "numeric",
});

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return tehranDT.format(d);
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${tehranTime.format(d)} (تهران)`;
}

export function fmtDayShort(iso: string, utc = true): string {
  const d = new Date(utc ? `${iso}T00:00:00Z` : iso);
  return tehranDay.format(d);
}

/** "۴ دقیقه پیش" style relative time in Persian. */
export function fmtAgo(iso: string | null | undefined): string {
  if (!iso) return "هیچ‌وقت";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return "همین حالا";
  const m = Math.floor(s / 60);
  if (m < 60) return `${faNum(m)} دقیقه پیش`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${faNum(h)} ساعت پیش`;
  const days = Math.floor(h / 24);
  if (days < 30) return `${faNum(days)} روز پیش`;
  return fmtDateTime(iso);
}

const FA_DIGITS = new Intl.NumberFormat("fa-IR");

/** Persian-digit group-formatted number (۱٬۲۳۴). */
export function faNum(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return FA_DIGITS.format(Math.round(n));
}

export function fmtSeconds(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 90) return `${faNum(Math.round(seconds))} ثانیه`;
  if (seconds < 5400) return `${faNum(Math.round(seconds / 60))} دقیقه`;
  if (seconds < 86400 * 2) return `${faNum(Math.round(seconds / 3600))} ساعت`;
  return `${faNum(Math.round(seconds / 86400))} روز`;
}

export function stateLabel(state: string | null | undefined): { label: string; tone: "ok" | "warn" | "danger" | "muted" | "accent" } {
  switch (state) {
    case "active": return { label: "آنلاین", tone: "ok" };
    case "stale": return { label: "بدون ضربان", tone: "warn" };
    case "revoked": return { label: "باطل‌شده", tone: "danger" };
    case "PENDING_APPROVAL": return { label: "در انتظار تأیید", tone: "warn" };
    case "APPROVED": return { label: "تأییدشده", tone: "accent" };
    case "ENROLLED": return { label: "تکمیل‌شده", tone: "ok" };
    case "REJECTED": return { label: "ردشده", tone: "danger" };
    case "EXPIRED": return { label: "منقضی", tone: "muted" };
    case "pending": case "queued": return { label: "در صف", tone: "warn" };
    case "dispatched": case "running": return { label: "در حال اجرا", tone: "accent" };
    case "succeeded": case "completed": return { label: "موفق", tone: "ok" };
    case "failed": case "error": return { label: "ناموفق", tone: "danger" };
    case "cancelled": return { label: "لغوشده", tone: "muted" };
    case "interrupted": return { label: "متوقف‌شده", tone: "warn" };
    default: return { label: state || "نامشخص", tone: "muted" };
  }
}

/** Suricata severity 1..4 → Persian label. */
export function severityLabel(sev: number): string {
  switch (sev) {
    case 1: return "بحرانی";
    case 2: return "مهم";
    case 3: return "متوسط";
    case 4: return "کم";
    default: return `سطح ${faNum(sev)}`;
  }
}
