import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useMemo } from "react";
import { api, hasToken, setToken } from "./lib/api";
import { ThemeProvider, useTheme } from "./lib/theme";
import { useLiveFeed } from "./lib/live";
import {
  IconGauge, IconAgents, IconInbox, IconWifi, IconShield, IconBrain,
  IconGear, IconSun, IconMoon, IconLogout,
} from "./components/icons";
import { TokenGate } from "./components/gate";
import OverviewPage from "./pages/Overview";
import AgentsPage from "./pages/Agents";
import PendingAgentsPage from "./pages/PendingAgents";
import AgentDetailPage from "./pages/AgentDetail";
import DiscoveryPage from "./pages/Discovery";
import SecurityPage from "./pages/Security";
import InvestigationsPage from "./pages/Investigations";
import AIActivityPage from "./pages/AIActivity";
import SettingsPage from "./pages/SettingsPage";

const NAV = [
  { to: "/dashboard", label: "نمای کلی", icon: IconGauge, exact: true },
  { to: "/dashboard/agents", label: "عامل‌ها", icon: IconAgents },
  { to: "/dashboard/pending", label: "در انتظار تأیید", icon: IconInbox },
  { to: "/dashboard/discovery", label: "کشف شبکه", icon: IconWifi },
  { to: "/dashboard/security", label: "مرکز امنیت", icon: IconShield },
  { to: "/dashboard/investigations", label: "بررسی‌های هوشمند", icon: IconBrain },
  { to: "/dashboard/ai-activity", label: "فعالیت هوش مصنوعی", icon: IconBrain },
  { to: "/dashboard/settings", label: "تنظیمات", icon: IconGear },
];

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-logo">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" aria-hidden="true">
            <circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none" />
            <circle cx="5" cy="6" r="2" />
            <circle cx="19" cy="6" r="2" />
            <circle cx="5" cy="18" r="2" />
            <circle cx="19" cy="18" r="2" />
            <path d="M6.8 7.2 10 10.6M17.2 7.2 14 10.6M6.8 16.8 10 13.4M17.2 16.8 14 13.4" />
          </svg>
        </div>
        <div className="brand-text small">
          عامل پایش و عیب‌یابی شبکه
          <small>داشبورد مدیریتی</small>
        </div>
      </div>
      <nav>
        <div className="nav-section">عملیات</div>
        {NAV.slice(0, 6).map(({ to, label, icon: Icon, exact }) => (
          <NavLink key={to} to={to} end={exact} className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
            <Icon size={18} />
            <span className="nav-label">{label}</span>
          </NavLink>
        ))}
        <div className="nav-section">سامانه</div>
        <NavLink to="/dashboard/settings" className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
          <IconGear size={18} />
          <span className="nav-label">تنظیمات</span>
        </NavLink>
      </nav>
      <div className="sidebar-footer">
        <div>مستندات فنی API:</div>
        <a href="/api/docs" target="_blank" rel="noreferrer" className="technical">/api/docs</a>
      </div>
    </aside>
  );
}

function AppBar() {
  const { theme, toggle } = useTheme();
  const feed = useLiveFeed(20000, async () => {
    try {
      await api.get("/api/dashboard/v1/healthz");
      return true;
    } catch {
      return false;
    }
  });
  const location = useLocation();
  const title = useMemo(() => {
    if (location.pathname.startsWith("/dashboard/agents/")) return "جزئیات عامل";
    const m = NAV.find((n) =>
      n.exact ? location.pathname === n.to : location.pathname === n.to,
    );
    return m?.label ?? "داشبورد";
  }, [location.pathname]);

  const tehranClock = new Intl.DateTimeFormat("fa-IR", {
    timeZone: "Asia/Tehran", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });

  return (
    <header className="appbar">
      <div>
        <div className="page-title">{title}</div>
      </div>
      <div className="spacer" />
      <span
        className={`connection-chip${feed.ok ? "" : " lost"}`}
        title={feed.ok ? "اتصال به هسته‌ی مرکزی برقرار است" : "ارتباط قطع است؛ داده‌ها قدیمی‌اند"}
      >
        <span className="dot" />
        {feed.ok ? "متصل" : "قطع"}
        {feed.ok && feed.lastSync !== null && (
          <span className="sync-fine">{tehranClock.format(feed.lastSync)}</span>
        )}
      </span>
      <button className="btn ghost sm" onClick={toggle} aria-label="تغییر پوسته" title={theme === "dark" ? "حالت روشن" : "حالت تیره"}>
        {theme === "dark" ? <IconSun size={16} /> : <IconMoon size={16} />}
      </button>
      <button
        className="btn ghost sm"
        onClick={() => { setToken(""); window.location.reload(); }}
        title="خروج (پاک‌کردن توکن از این مرورگر)"
      >
        <IconLogout size={16} />
      </button>
    </header>
  );
}

function ShellInner() {
  if (!hasToken()) {
    return (
      <div style={{ display: "grid", placeItems: "center", minHeight: "100vh", padding: 20 }}>
        <TokenGate />
      </div>
    );
  }
  return (
    <div className="shell">
      <Sidebar />
      <div className="shell-content">
        <AppBar />
        <main className="page">
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
            <Route path="/dashboard/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ShellInner />
    </ThemeProvider>
  );
}
