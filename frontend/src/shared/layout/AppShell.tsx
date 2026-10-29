// Shared layout — AppShell wraps all authenticated pages with sidebar + topbar

import { type FC, type ReactNode, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity,
  BarChart3,
  Bell,
  ChevronLeft,
  ChevronRight,
  Clock,
  Globe,
  LayoutDashboard,
  LineChart,
  Menu,
  Search,
  Shield,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react'
import { cn } from '../lib/utils'

// ---------------------------------------------------------------------------
// Nav items config
// ---------------------------------------------------------------------------

interface NavItem {
  label: string
  to: string
  icon: FC<{ className?: string }>
  badge?: string
  badgeVariant?: 'violet' | 'coral' | 'emerald' | 'amber'
}

interface NavSection {
  title: string
  items: NavItem[]
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Operations',
    items: [
      { label: 'Analyze Email', to: '/analyze', icon: Zap },
      { label: 'Security Overview', to: '/dashboard', icon: LayoutDashboard },
      { label: 'Analysis History', to: '/history', icon: Clock },
    ],
  },
  {
    title: 'Threat Intelligence',
    items: [
      { label: 'Deep Analytics', to: '/analytics', icon: LineChart },
      { label: 'Threat Intelligence', to: '/threat-intel', icon: Globe },
      { label: 'Compliance Reports', to: '/reports', icon: BarChart3 },
    ],
  },
]

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
  mobileOpen: boolean
  onMobileClose: () => void
}

const Sidebar: FC<SidebarProps> = ({ collapsed, onToggle, mobileOpen, onMobileClose }) => {
  const location = useLocation()

  const navLinkClass = (to: string) => {
    const active = location.pathname === to || (to !== '/' && location.pathname.startsWith(to))
    return cn(
      'group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-medium transition-all duration-150',
      active
        ? 'bg-violet-50 text-violet-700 font-semibold shadow-xs ring-1 ring-violet-200/70'
        : 'text-slate-600 hover:bg-slate-100/80 hover:text-slate-900',
    )
  }

  const sidebarContent = (
    <div className="flex h-full flex-col bg-white">
      {/* Brand */}
      <div
        className={cn(
          'flex h-16 shrink-0 items-center border-b border-slate-150 px-4.5',
          collapsed ? 'justify-center' : 'gap-3',
        )}
      >
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-tr from-violet-700 to-indigo-600 text-white shadow-violet-sm shadow-sm ring-1 ring-white/20">
          <ShieldCheck className="h-5 w-5" />
        </span>
        {!collapsed && (
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-bold tracking-tight text-slate-900">
                ThreatGuard
              </span>
              <span className="rounded-md bg-violet-100 px-1.5 py-0.2 text-[10px] font-bold text-violet-700">
                PRO
              </span>
            </div>
            <p className="text-2xs font-medium text-slate-400 uppercase tracking-wider">
              Autonomous Defense
            </p>
          </div>
        )}
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className="space-y-1">
            {!collapsed && (
              <h4 className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                {section.title}
              </h4>
            )}
            {section.items.map((item) => {
              const isActive =
                location.pathname === item.to ||
                (item.to !== '/' && location.pathname.startsWith(item.to))
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={onMobileClose}
                  className={navLinkClass(item.to)}
                  title={collapsed ? item.label : undefined}
                >
                  {/* Left indicator bar on active */}
                  {isActive && !collapsed && (
                    <span className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r-full bg-violet-600" />
                  )}
                  <item.icon
                    className={cn(
                      'h-4.5 w-4.5 shrink-0 transition-colors',
                      isActive
                        ? 'text-violet-600'
                        : 'text-slate-400 group-hover:text-slate-700',
                    )}
                  />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                  {!collapsed && item.badge && (
                    <span className="ml-auto rounded-full bg-coral-500 px-1.5 py-0.5 text-2xs font-bold text-white">
                      {item.badge}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Engine & Tenant Status Box */}
      <div
        className={cn(
          'border-t border-slate-150 p-3',
          collapsed ? 'flex justify-center' : '',
        )}
      >
        {!collapsed ? (
          <div className="rounded-xl border border-slate-200/80 bg-slate-50/80 p-3 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide">
                Security Gateway
              </span>
              <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                HEALTHY
              </span>
            </div>
            <div className="space-y-1 text-2xs text-slate-500">
              <div className="flex justify-between">
                <span>Tenant:</span>
                <span className="font-mono text-slate-700">default-tenant</span>
              </div>
              <div className="flex justify-between">
                <span>Engines:</span>
                <span className="font-medium text-slate-700">6/6 Operational</span>
              </div>
            </div>
          </div>
        ) : (
          <span
            className="flex h-8 w-8 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600"
            title="Gateway Healthy"
          >
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
          </span>
        )}
      </div>

      {/* Collapse toggle (desktop) */}
      <button
        type="button"
        onClick={onToggle}
        className="absolute -right-3 top-20 flex h-6 w-6 items-center justify-center rounded-full border border-slate-200 bg-white shadow-sm text-slate-500 hover:text-violet-600 hover:border-violet-300 transition-colors"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronLeft className="h-3.5 w-3.5" />}
      </button>
    </div>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'relative hidden lg:flex flex-col border-r border-neutral-100 bg-white transition-all duration-200 ease-in-out',
          collapsed ? 'w-[68px]' : 'w-62',
        )}
      >
        {sidebarContent}
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/30 lg:hidden"
            aria-hidden="true"
            onClick={onMobileClose}
          />
          <aside className="fixed inset-y-0 left-0 z-50 w-72 flex flex-col border-r border-neutral-100 bg-white shadow-xl lg:hidden">
            <button
              type="button"
              className="absolute right-3 top-4 rounded-lg p-1.5 text-neutral-500 hover:bg-neutral-100"
              onClick={onMobileClose}
              aria-label="Close navigation"
            >
              <X className="h-5 w-5" />
            </button>
            {sidebarContent}
          </aside>
        </>
      )}
    </>
  )
}

// ---------------------------------------------------------------------------
// TopBar
// ---------------------------------------------------------------------------

interface TopBarProps {
  onMobileMenuOpen: () => void
}

const TopBar: FC<TopBarProps> = ({ onMobileMenuOpen }) => {
  const location = useLocation()

  const allNavItems = NAV_SECTIONS.flatMap((s) => s.items)
  const pageTitle =
    allNavItems.find((n) => location.pathname === n.to || (n.to !== '/' && location.pathname.startsWith(n.to)))?.label ?? 'Threat Operations'

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-4 border-b border-slate-200/80 bg-white/95 px-4 backdrop-blur-md sm:px-6">
      {/* Mobile hamburger */}
      <button
        type="button"
        className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 lg:hidden"
        onClick={onMobileMenuOpen}
        aria-label="Open navigation"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-xs">
        <span className="flex items-center gap-1.5 font-medium text-slate-400">
          <Shield className="h-3.5 w-3.5 text-violet-500" />
          <span>ThreatGuard</span>
        </span>
        <span className="text-slate-300">/</span>
        <span className="font-semibold text-slate-800">{pageTitle}</span>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Search */}
      <div className="hidden sm:flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50/80 px-3 py-1.5 text-sm text-slate-400 hover:border-violet-300 hover:bg-violet-50/20 transition-all cursor-text w-64 shadow-2xs">
        <Search className="h-3.5 w-3.5 shrink-0 text-slate-400" />
        <span className="text-xs text-slate-500">Search indicators, hashes, senders...</span>
        <kbd className="ml-auto rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-mono text-slate-400 shadow-2xs">
          ⌘K
        </kbd>
      </div>

      {/* Notifications */}
      <button
        type="button"
        className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-neutral-200 bg-white text-neutral-500 shadow-xs hover:border-violet-300 hover:text-violet-600 transition-colors"
        aria-label="Notifications"
      >
        <Bell className="h-4.5 w-4.5" />
        <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-coral-500 text-2xs font-bold text-white">
          3
        </span>
      </button>

      {/* Activity */}
      <button
        type="button"
        className="hidden sm:flex h-9 w-9 items-center justify-center rounded-xl border border-neutral-200 bg-white text-neutral-500 shadow-xs hover:border-violet-300 hover:text-violet-600 transition-colors"
        aria-label="Activity log"
      >
        <Activity className="h-4.5 w-4.5" />
      </button>

      {/* User avatar */}
      <button
        type="button"
        className="flex h-9 w-9 items-center justify-center rounded-xl bg-violet-100 text-sm font-bold text-violet-700 hover:bg-violet-200 transition-colors"
        aria-label="User menu"
      >
        Y
      </button>
    </header>
  )
}

// ---------------------------------------------------------------------------
// AppShell
// ---------------------------------------------------------------------------

interface AppShellProps {
  children: ReactNode
}

export const AppShell: FC<AppShellProps> = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="flex h-screen overflow-hidden bg-neutral-50">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((v) => !v)}
        mobileOpen={mobileMenuOpen}
        onMobileClose={() => setMobileMenuOpen(false)}
      />

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar onMobileMenuOpen={() => setMobileMenuOpen(true)} />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</div>
        </main>
      </div>
    </div>
  )
}
