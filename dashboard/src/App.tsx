import { Navigate, NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { lazy, Suspense, useEffect, useState, useSyncExternalStore } from "react";
import { api, hasToken, setToken, subscribeAuth } from "./lib/api";
import { ThemeProvider, useTheme } from "./lib/theme";
import { useLiveFeed } from "./lib/live";
import {
  IconGauge, IconAgents, IconInbox, IconWifi, IconShield, IconBrain,
  IconGear, IconSun, IconMoon, IconLogout, IconBook, IconHeartbeat,
  IconCheck, IconMenu, IconX, IconChevron, IconNodes, IconSearch,
} from "./components/icons";
import { TokenGate } from "./components/gate";
import { Dialog, EmptyState, SkeletonRows } from "./components/ui";

const OverviewPage = lazy(() => import("./pages/Overview"));
const AgentsPage = lazy(() => import("./pages/Agents"));
const PendingAgentsPage = lazy(() => import("./pages/PendingAgents"));
const AgentDetailPage = lazy(() => import("./pages/AgentDetail"));
const DiscoveryPage = lazy(() => import("./pages/Discovery"));
const SecurityPage = lazy(() => import("./pages/Security"));
const InvestigationsPage = lazy(() => import("./pages/Investigations"));
const AIActivityPage = lazy(() => import("./pages/AIActivity"));
const AIKnowledgePage = lazy(() => import("./pages/AIKnowledge"));
const AIActionsPage = lazy(() => import("./pages/AIActions"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

const NAV = [
  { to: "/dashboard", label: "نمای کلی", icon: IconGauge, group: "پایش و عملیات", description: "دید یکپارچه از شبکه، هشدارها و کارهای در انتظار شما.", code: "OVERVIEW" },
  { to: "/dashboard/security", label: "مرکز امنیت", icon: IconShield, group: "پایش و عملیات", description: "از رویداد تا بینش؛ تحلیل امنیت با کنترل مستقیم شما.", code: "SECURITY OPERATIONS" },
  { to: "/dashboard/agents", label: "عامل‌ها", icon: IconAgents, group: "پایش و عملیات", description: "وضعیت ارتباط، موجودی سیستم و ابزارهای مدیریت نقاط پایانی.", code: "ENDPOINTS" },
  { to: "/dashboard/discovery", label: "کشف شبکه", icon: IconWifi, group: "پایش و عملیات", description: "شبکه‌های مشاهده‌شده و محدودهٔ مجاز برای کشف و عیب‌یابی.", code: "NETWORK DISCOVERY" },
  { to: "/dashboard/investigations", label: "بررسی‌های هوشمند", icon: IconBrain, group: "هوش و تحلیل", description: "بررسی شواهد شبکه و پاسخ به پرسش‌های عملیاتی.", code: "INVESTIGATIONS" },
  { to: "/dashboard/ai-activity", label: "فعالیت هوش مصنوعی", icon: IconHeartbeat, group: "هوش و تحلیل", description: "خط زمانی درخواست‌های واقعی، زمان پاسخ و وضعیت مدل محلی.", code: "AI ACTIVITY" },
  { to: "/dashboard/ai-knowledge", label: "حافظهٔ هوشمند", icon: IconBook, group: "هوش و تحلیل", description: "دانش تأییدشدهٔ شبکه و پرسش از مدل بر پایهٔ شواهد.", code: "KNOWLEDGE" },
  { to: "/dashboard/ai-actions", label: "پیشنهادهای هوشمند", icon: IconCheck, group: "هوش و تحلیل", description: "پیشنهادهای مدل برای بررسی و تصمیم صریح مدیر.", code: "ACTION PROPOSALS" },
  { to: "/dashboard/pending", label: "در انتظار تأیید", icon: IconInbox, group: "مدیریت", description: "بازبینی هویت دستگاه‌ها و تصمیم دربارهٔ ورود به شبکهٔ مدیریت.", code: "APPROVAL DESK" },
  { to: "/dashboard/settings", label: "تنظیمات", icon: IconGear, group: "مدیریت", description: "پیکربندی هسته، اتصال مدل و ترجیحات این مرورگر.", code: "CONFIGURATION" },
];

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  return <>
    {open && <button className="nav-backdrop" aria-label="بستن منو" onClick={onClose} />}
    <aside id="main-navigation" className={`sidebar${open ? " is-open" : ""}`}>
      <NavLink to="/dashboard" className="brand" onClick={onClose}>
        <span className="brand-logo"><IconNodes size={24} /></span>
        <span className="brand-text"><b dir="ltr">NetAgent<span className="brand-period">.</span></b><small>مرکز عملیات شبکه</small></span>
      </NavLink>
      <button className="btn ghost sm nav-close" aria-label="بستن منو" onClick={onClose}><IconX size={18} /></button>
      <nav aria-label="ناوبری اصلی">
        {["پایش و عملیات", "هوش و تحلیل", "مدیریت"].map((group) => <div key={group} className="nav-group">
          <div className="nav-section">{group}</div>
          {NAV.filter((item) => item.group === group).map(({ to, label, icon: Icon }) =>
            <NavLink key={to} to={to} end={to === "/dashboard"} title={label} onClick={onClose}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
              <Icon size={18} /><span className="nav-label">{label}</span>
            </NavLink>)}
        </div>)}
      </nav>
      <div className="sidebar-footer">
        <div className="sidebar-footnote"><IconShield size={16} /><span>پایش، بررسی و تصمیم آگاهانه</span></div>
        <a href="/api/docs" target="_blank" rel="noreferrer">مستندات API <IconChevron size={13} /></a>
        <span className="sidebar-caption" dir="ltr">LOCAL INTELLIGENCE · NETWORK VISIBILITY</span>
      </div>
    </aside>
  </>;
}

function QuickNavigation({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const needle = query.trim().toLowerCase();
  const matches = NAV.filter((item) => `${item.label} ${item.code} ${item.description}`.toLowerCase().includes(needle));
  const go = (to: string) => { onClose(); navigate(to); };
  return <Dialog title="دسترسی سریع به فضای کاری" onClose={onClose}>
    <label className="quick-search"><IconSearch size={18} /><input className="input" autoFocus
      aria-label="جست‌وجوی صفحه‌ها" placeholder="نام صفحه یا قابلیت را بنویسید…" value={query}
      onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => {
        if (e.key === "Enter" && matches.length) { e.preventDefault(); go(matches[0].to); }
      }} /></label>
    <div className="quick-results">
      {matches.map(({ to, label, icon: Icon, description, group }) => <button key={to} className="quick-result" onClick={() => go(to)}>
        <span className="quick-result-icon"><Icon size={18} /></span><span className="quick-result-copy"><b>{label}</b><small>{description}</small></span>
        <span className="quick-result-group">{group}</span><IconChevron size={13} />
      </button>)}
      {!matches.length && <EmptyState title="صفحه‌ای پیدا نشد" hint="نام فارسی صفحه یا نام انگلیسی قابلیت را امتحان کنید." />}
    </div>
    <p className="small muted quick-hint">با کلید Tab مقصد را انتخاب کنید؛ Enter باز می‌کند و Escape می‌بندد.</p>
  </Dialog>;
}

function AppBar({ onMenu, menuOpen, onNavigate }: { onMenu: () => void; menuOpen: boolean; onNavigate: () => void }) {
  const { theme, toggle } = useTheme();
  const feed = useLiveFeed(20000, async () => {
    await api.get("/api/dashboard/v1/healthz");
    return true;
  });
  const location = useLocation();
  const title = location.pathname.startsWith("/dashboard/agents/") ? "جزئیات عامل" : NAV.find((n) => n.to === location.pathname)?.label ?? "نمای کلی";
  return <header className="appbar">
    <button className="btn ghost icon-btn nav-menu" onClick={onMenu} aria-label="بازکردن منوی ناوبری" aria-expanded={menuOpen} aria-controls="main-navigation"><IconMenu size={20} /></button>
    <div className="breadcrumb"><IconNodes size={16} /><span>مرکز عملیات</span><IconChevron size={12} /><b>{title}</b></div>
    <div className="spacer" />
    <button className="btn ghost quick-trigger" aria-label="دسترسی سریع" onClick={onNavigate} title="دسترسی سریع (Ctrl+K)"><IconSearch size={16} /><span>دسترسی سریع</span><kbd dir="ltr">Ctrl K</kbd></button>
    <span className={`connection-chip${!feed.checked ? " checking" : feed.ok ? "" : " lost"}`} role="status"
      title={feed.ok && feed.lastSync ? "اتصال به هستهٔ مرکزی برقرار است" : "داده‌های قبلی ممکن است به‌روز نباشند"}>
      <span className="dot" />{!feed.checked ? "بررسی اتصال" : feed.ok ? "هسته متصل" : "ارتباط قطع"}
    </span>
    <div className="appbar-actions">
      <button className="btn ghost icon-btn" onClick={toggle} aria-label="تغییر پوسته" title={theme === "dark" ? "حالت روشن" : "حالت تیره"}>
        {theme === "dark" ? <IconSun size={18} /> : <IconMoon size={18} />}
      </button>
      <button className="btn ghost icon-btn" onClick={() => setToken("")} aria-label="خروج از داشبورد" title="خروج"><IconLogout size={17} /></button>
      <span className="operator-avatar" title="مدیر شبکه">م</span>
    </div>
  </header>;
}

function ShellInner() {
  const authenticated = useSyncExternalStore(subscribeAuth, hasToken);
  const [menuOpen, setMenuOpen] = useState(false);
  const [quickOpen, setQuickOpen] = useState(false);
  const location = useLocation();
  useEffect(() => { setMenuOpen(false); }, [location.pathname]);
  useEffect(() => {
    if (!authenticated) { setQuickOpen(false); return; }
    const shortcut = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k" && !e.isComposing
          && !(e.target instanceof Element && e.target.closest("input, textarea, [contenteditable=true]"))) {
        e.preventDefault(); setMenuOpen(false); setQuickOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", shortcut);
    return () => document.removeEventListener("keydown", shortcut);
  }, [authenticated]);
  useEffect(() => {
    if (!menuOpen) return;
    const escape = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [menuOpen]);
  if (!authenticated) return <TokenGate />;
  const meta = location.pathname.startsWith("/dashboard/agents/")
    ? { ...NAV[2], label: "جزئیات عامل", code: "ENDPOINT WORKSPACE" }
    : NAV.find((n) => n.to === location.pathname) ?? NAV[0];
  return <div className="shell">
    <a className="skip-link" href="#page-content">رفتن به محتوای صفحه</a>
    <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
    <div className="shell-content">
      <AppBar onMenu={() => setMenuOpen((v) => !v)} menuOpen={menuOpen} onNavigate={() => { setMenuOpen(false); setQuickOpen(true); }} />
      <main className="page" id="page-content">
        <div className="page-heading">
          <div><div className="eyebrow" dir="ltr">{meta.code}</div><h1>{meta.label}</h1><p>{meta.description}</p></div>
          <div className="page-heading-context"><span className="date-line">{new Intl.DateTimeFormat("fa-IR", { dateStyle: "full", timeZone: "Asia/Tehran" }).format(new Date())}</span><span className="small muted">فضای کاری مدیر شبکه</span></div>
        </div>
        <Suspense fallback={<div className="card" role="status" aria-label="در حال بارگیری صفحه"><SkeletonRows /></div>}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<OverviewPage />} />
            <Route path="/dashboard/agents" element={<AgentsPage />} />
            <Route path="/dashboard/pending" element={<PendingAgentsPage />} />
            <Route path="/dashboard/agents/:agentId" element={<AgentDetailPage />} />
            <Route path="/dashboard/discovery" element={<DiscoveryPage />} />
            <Route path="/dashboard/security" element={<SecurityPage />} />
            <Route path="/dashboard/investigations" element={<InvestigationsPage />} />
            <Route path="/dashboard/ai-activity" element={<AIActivityPage />} />
            <Route path="/dashboard/ai-knowledge" element={<AIKnowledgePage />} />
            <Route path="/dashboard/ai-actions" element={<AIActionsPage />} />
            <Route path="/dashboard/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </Suspense>
        <footer className="page-footer"><span dir="ltr">NetAgent / Network Operations</span><span>داده‌های واقعی · تحلیل محلی · تصمیم با مدیر</span></footer>
      </main>
    </div>
    {quickOpen && <QuickNavigation onClose={() => setQuickOpen(false)} />}
  </div>;
}

export default function App() {
  return <ThemeProvider><ShellInner /></ThemeProvider>;
}
