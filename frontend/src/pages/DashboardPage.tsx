import { type FC, useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  Bot,
  Clock,
  FileSpreadsheet,
  FileWarning,
  Key,
  Mail,
  RefreshCw,
  UserX,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react'
import { dashboardApi } from '../shared/api/dashboard.api'
import {
  Alert,
  Button,
  Card,
  Skeleton,
} from '../shared/ui'
import { AppShell } from '../shared/layout/AppShell'
import { useDashboardWebSocket } from '../features/dashboard/useDashboardWebSocket'
import {
  AttackTypeDistributionChart,
  DetectionTrendsChart,
  LLMUsageTelemetryCard,
  ProcessingTimeChart,
  RecentThreatsTable,
  RiskDistributionChart,
  SeverityDistributionChart,
  ThreatsOverTimeChart,
} from '../features/dashboard/DashboardCharts'
import { cn } from '../shared/lib/utils'

// ---------------------------------------------------------------------------
// Metric Card Component
// ---------------------------------------------------------------------------

interface HeroMetricCardProps {
  label: string
  value: string | number
  subtext?: string
  badgeText?: string
  badgeVariant?: 'critical' | 'warning' | 'success' | 'violet' | 'coral' | 'emerald'
  icon: FC<{ className?: string }>
  iconBg: string
  iconColor: string
  highlight?: 'critical' | 'warning' | 'success' | 'primary'
  loading?: boolean
  children?: React.ReactNode
}

const HeroMetricCard: FC<HeroMetricCardProps> = ({
  label,
  value,
  subtext,
  badgeText,
  badgeVariant = 'violet',
  icon: Icon,
  iconBg,
  iconColor,
  loading,
  children,
}) => {
  if (loading) {
    return (
      <Card className="p-5 space-y-3 bg-white border border-slate-200 shadow-xs">
        <Skeleton className="h-3 w-1/3" />
        <Skeleton className="h-9 w-1/2" />
        <Skeleton className="h-4 w-2/3" />
      </Card>
    )
  }

  const badgeClasses = {
    critical: 'bg-rose-50 text-rose-700 border-rose-200/80',
    warning: 'bg-amber-50 text-amber-700 border-amber-200/80',
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200/80',
    emerald: 'bg-emerald-50 text-emerald-700 border-emerald-200/80',
    violet: 'bg-violet-50 text-violet-700 border-violet-200/80',
    coral: 'bg-orange-50 text-orange-700 border-orange-200/80',
  }[badgeVariant]

  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-200/90 bg-white p-5 shadow-xs hover:shadow-md hover:border-slate-300 transition-all duration-200 group">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1.5 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              {label}
            </span>
            {badgeText && (
              <span className={cn('rounded-full px-2 py-0.5 text-[10px] font-semibold border', badgeClasses)}>
                {badgeText}
              </span>
            )}
          </div>
          <p className="text-3xl font-extrabold tabular-nums tracking-tight text-slate-900 group-hover:text-violet-900 transition-colors">
            {value}
          </p>
          {subtext && <p className="text-xs text-slate-500">{subtext}</p>}
        </div>

        <span
          className={cn(
            'flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl shadow-2xs transition-transform duration-200 group-hover:scale-105',
            iconBg,
          )}
        >
          <Icon className={cn('h-6 w-6', iconColor)} />
        </span>
      </div>
      {children && <div className="mt-4 pt-3 border-t border-slate-100">{children}</div>}
    </div>
  )
}

interface VectorMetricCardProps {
  label: string
  value: string | number
  subtext?: string
  icon: FC<{ className?: string }>
  iconBg: string
  iconColor: string
  countAlert?: boolean
  loading?: boolean
}

const VectorMetricCard: FC<VectorMetricCardProps> = ({
  label,
  value,
  subtext,
  icon: Icon,
  iconBg,
  iconColor,
  countAlert,
  loading,
}) => {
  if (loading) {
    return (
      <Card className="p-3.5 space-y-2">
        <Skeleton className="h-3 w-1/2" />
        <Skeleton className="h-6 w-1/3" />
      </Card>
    )
  }

  return (
    <div className="group rounded-xl border border-slate-200/80 bg-white p-3.5 shadow-2xs hover:shadow-sm hover:border-slate-300 transition-all duration-150">
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 truncate">
            {label}
          </p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className={cn(
              'text-xl font-bold tabular-nums tracking-tight',
              countAlert ? 'text-rose-600' : 'text-slate-800',
            )}>
              {value}
            </span>
          </div>
          {subtext && <p className="text-[10px] text-slate-400 truncate mt-0.5">{subtext}</p>}
        </div>
        <span
          className={cn(
            'flex h-8 w-8 shrink-0 items-center justify-center rounded-xl',
            iconBg,
          )}
        >
          <Icon className={cn('h-4 w-4', iconColor)} />
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Dashboard Page Component
// ---------------------------------------------------------------------------

export function DashboardPage() {
  const [timeWindowDays, setTimeWindowDays] = useState<number>(14)
  const [liveToast, setLiveToast] = useState<{
    show: boolean
    verdict: string
    score: number
  } | null>(null)

  // Handle incoming live WebSocket telemetry event
  const handleWsEvent = useCallback(
    (event: { data?: { verdict?: string; risk_score?: number } }) => {
      if (event.data?.verdict) {
        setLiveToast({
          show: true,
          verdict: event.data.verdict,
          score: event.data.risk_score || 0,
        })
        setTimeout(() => setLiveToast(null), 5000)
      }
    },
    [],
  )

  // Live WebSocket connection with automatic polling fallback
  const { isConnected } = useDashboardWebSocket(handleWsEvent)
  const pollInterval = isConnected ? 60_000 : 15_000

  // TanStack Queries for authoritative backend data
  const {
    data: metrics,
    isLoading: metricsLoading,
    isError: metricsError,
    error: metricsErr,
    refetch: refetchMetrics,
    isFetching: metricsFetching,
  } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: () => dashboardApi.getMetrics(),
    staleTime: 10_000,
    refetchInterval: pollInterval,
  })

  const {
    data: charts,
    isLoading: chartsLoading,
    isError: chartsError,
    error: chartsErr,
    refetch: refetchCharts,
    isFetching: chartsFetching,
  } = useQuery({
    queryKey: ['dashboard-charts', timeWindowDays],
    queryFn: () => dashboardApi.getCharts(timeWindowDays),
    staleTime: 10_000,
    refetchInterval: pollInterval,
  })

  const isBusy = metricsFetching || chartsFetching

  const refreshAll = () => {
    refetchMetrics()
    refetchCharts()
  }

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Live analysis toast alert */}
        {liveToast && (
          <div className="animate-slide-in-right rounded-xl border border-violet-200 bg-violet-50 p-3 shadow-md flex items-center justify-between">
            <div className="flex items-center gap-2.5 text-xs text-violet-900">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-violet-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-violet-600" />
              </span>
              <span>
                <strong>Analysis event received:</strong> New email categorized as{' '}
                <span className="capitalize font-bold text-violet-700">
                  {liveToast.verdict}
                </span>{' '}
                (Risk Score: {liveToast.score})
              </span>
            </div>
            <button
              type="button"
              onClick={() => setLiveToast(null)}
              className="text-xs text-violet-600 hover:text-violet-800"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Page Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-neutral-900">
                Security Operations Dashboard
              </h1>
              {isConnected ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-success-200 bg-success-50 px-2.5 py-0.5 text-2xs font-semibold text-success-700">
                  <Wifi className="h-3 w-3 text-success-600" />
                  Live Sync Active
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-neutral-200 bg-neutral-100 px-2.5 py-0.5 text-2xs font-medium text-neutral-500">
                  <WifiOff className="h-3 w-3 text-neutral-400" />
                  Connecting Socket...
                </span>
              )}
            </div>
            <p className="text-xs text-neutral-500 mt-0.5">
              Real-time threat intelligence and automated detection telemetry backed by PostgreSQL
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Time Window Selector */}
            <div className="flex items-center rounded-xl border border-neutral-200 bg-white p-1 text-xs shadow-xs">
              {[
                { label: '7D', days: 7 },
                { label: '14D', days: 14 },
                { label: '30D', days: 30 },
              ].map(({ label, days }) => (
                <button
                  key={days}
                  type="button"
                  onClick={() => setTimeWindowDays(days)}
                  className={cn(
                    'rounded-lg px-2.5 py-1 font-semibold transition-all',
                    timeWindowDays === days
                      ? 'bg-violet-600 text-white shadow-xs'
                      : 'text-neutral-500 hover:text-neutral-900',
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            <Button
              variant="outline"
              size="sm"
              loading={isBusy}
              onClick={refreshAll}
              leftIcon={<RefreshCw className="h-3.5 w-3.5" />}
            >
              Refresh
            </Button>

            <Link to="/analyze">
              <Button
                variant="primary"
                size="sm"
                leftIcon={<Zap className="h-3.5 w-3.5" />}
                rightIcon={<ArrowUpRight className="h-3.5 w-3.5" />}
              >
                Analyze Email
              </Button>
            </Link>
          </div>
        </div>

        {/* Global Error Notice if API fails */}
        {(metricsError || chartsError) && (
          <Alert
            variant="error"
            title="Failed to fetch dashboard data"
            icon={<AlertCircle className="h-5 w-5" />}
          >
            <p>
              {metricsErr instanceof Error ? metricsErr.message : ''}{' '}
              {chartsErr instanceof Error ? chartsErr.message : ''}
            </p>
            <button
              type="button"
              onClick={refreshAll}
              className="mt-2 text-xs font-semibold text-danger-700 underline"
            >
              Retry Connection
            </button>
          </Alert>
        )}

        {/* -------------------------------------------------------------------
            Hero KPI Tier (Top 3 Posture Anchors)
        ------------------------------------------------------------------- */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Threat Posture & Ingestion Telemetry
              </h2>
              <p className="text-2xs text-slate-400">
                Real-time security telemetry processed through multi-layer verification pipeline
              </p>
            </div>
            <span className="hidden sm:inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-0.5 text-2xs font-semibold text-slate-600">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Live Stream
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {/* Hero 1: Total Processed & Clean Ratio */}
            <HeroMetricCard
              label="Ingestion Volume"
              value={metrics?.total_emails_analyzed ?? 0}
              subtext="Analyzed emails across all active tenants"
              badgeText={`${metrics ? (metrics.total_emails_analyzed - metrics.threats_detected) : 0} Clean`}
              badgeVariant="success"
              icon={Mail}
              iconBg="bg-violet-50"
              iconColor="text-violet-600"
              loading={metricsLoading}
            >
              <div className="flex items-center justify-between text-2xs text-slate-500">
                <span>Inspection mode: Full Pipeline</span>
                <span className="font-semibold text-violet-700">100% Inspected</span>
              </div>
            </HeroMetricCard>

            {/* Hero 2: Active Threats Detected */}
            <HeroMetricCard
              label="Threats Intercepted"
              value={metrics?.threats_detected ?? 0}
              subtext={`${metrics?.critical_threats ?? 0} critical, ${metrics?.high_risk_emails ?? 0} high risk`}
              badgeText={
                metrics && metrics.total_emails_analyzed > 0
                  ? `${Math.round((metrics.threats_detected / metrics.total_emails_analyzed) * 100)}% Threat Ratio`
                  : '0% Threat Ratio'
              }
              badgeVariant="critical"
              icon={AlertTriangle}
              iconBg="bg-rose-50"
              iconColor="text-rose-600"
              loading={metricsLoading}
            >
              <div className="flex items-center gap-2">
                <div className="h-2 flex-1 rounded-full bg-slate-100 overflow-hidden flex">
                  <div
                    className="bg-rose-500 h-full"
                    style={{
                      width: `${
                        metrics && metrics.threats_detected > 0
                          ? ((metrics.critical_threats / metrics.threats_detected) * 100)
                          : 0
                      }%`,
                    }}
                    title="Critical"
                  />
                  <div
                    className="bg-orange-500 h-full"
                    style={{
                      width: `${
                        metrics && metrics.threats_detected > 0
                          ? ((metrics.high_risk_emails / metrics.threats_detected) * 100)
                          : 0
                      }%`,
                    }}
                    title="High"
                  />
                </div>
                <span className="text-[10px] font-bold text-slate-500 tabular-nums">
                  {metrics?.critical_threats ?? 0} crit / {metrics?.high_risk_emails ?? 0} high
                </span>
              </div>
            </HeroMetricCard>

            {/* Hero 3: Pipeline Latency & Health */}
            <HeroMetricCard
              label="Pipeline Performance"
              value={
                metrics
                  ? metrics.average_analysis_latency_ms < 1000
                    ? `${metrics.average_analysis_latency_ms}ms`
                    : `${(metrics.average_analysis_latency_ms / 1000).toFixed(2)}s`
                  : '0ms'
              }
              subtext={`End-to-end P95 analysis turnaround time`}
              badgeText={`${metrics?.analysis_success_rate ?? 100}% Reliability`}
              badgeVariant="emerald"
              icon={Clock}
              iconBg="bg-teal-50"
              iconColor="text-teal-600"
              loading={metricsLoading}
            >
              <div className="flex items-center justify-between text-2xs text-slate-500">
                <span>Multi-tier analyzer engines</span>
                <span className="font-semibold text-emerald-700">Healthy & Online</span>
              </div>
            </HeroMetricCard>
          </div>
        </div>

        {/* -------------------------------------------------------------------
            Secondary Threat Vectors & Engine Signals
        ------------------------------------------------------------------- */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Detected Attack Vectors & Security Signals
          </h3>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <VectorMetricCard
              label="Phishing Lures"
              value={metrics?.phishing_count ?? 0}
              subtext="Heuristic + ML"
              icon={FileWarning}
              iconBg="bg-rose-50"
              iconColor="text-rose-600"
              countAlert={metrics ? metrics.phishing_count > 0 : false}
              loading={metricsLoading}
            />

            <VectorMetricCard
              label="BEC / Impersonation"
              value={metrics?.bec_count ?? 0}
              subtext="Executive spoofing"
              icon={UserX}
              iconBg="bg-orange-50"
              iconColor="text-orange-600"
              countAlert={metrics ? metrics.bec_count > 0 : false}
              loading={metricsLoading}
            />

            <VectorMetricCard
              label="Credential Theft"
              value={metrics?.credential_theft_count ?? 0}
              subtext="Harvesting links"
              icon={Key}
              iconBg="bg-amber-50"
              iconColor="text-amber-600"
              countAlert={metrics ? metrics.credential_theft_count > 0 : false}
              loading={metricsLoading}
            />

            <VectorMetricCard
              label="Malware Payloads"
              value={metrics?.malware_related_events ?? 0}
              subtext="Dangerous files"
              icon={FileSpreadsheet}
              iconBg="bg-rose-50"
              iconColor="text-rose-600"
              countAlert={metrics ? metrics.malware_related_events > 0 : false}
              loading={metricsLoading}
            />

            <VectorMetricCard
              label="Mean Risk Score"
              value={metrics ? `${metrics.average_risk_score}/100` : '0/100'}
              subtext="Platform average"
              icon={Activity}
              iconBg="bg-violet-50"
              iconColor="text-violet-600"
              loading={metricsLoading}
            />

            <VectorMetricCard
              label="LLM Invocations"
              value={metrics?.llm_usage.total_calls ?? 0}
              subtext={`${metrics?.llm_usage.analyzed_calls ?? 0} deep scans`}
              icon={Bot}
              iconBg="bg-indigo-50"
              iconColor="text-indigo-600"
              loading={metricsLoading}
            />
          </div>
        </div>

        {/* -------------------------------------------------------------------
            8 Responsive Charts Layout
        ------------------------------------------------------------------- */}
        <div className="space-y-6">
          {/* Row 1: Threats Over Time (2 cols) & Risk Distribution (1 col) */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ThreatsOverTimeChart
                data={charts?.threats_over_time ?? []}
                loading={chartsLoading}
              />
            </div>
            <div>
              <RiskDistributionChart
                data={charts?.risk_distribution ?? []}
                loading={chartsLoading}
              />
            </div>
          </div>

          {/* Row 2: Attack Type Distribution & Severity Distribution & Processing Time */}
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            <AttackTypeDistributionChart
              data={charts?.attack_type_distribution ?? []}
              loading={chartsLoading}
            />
            <SeverityDistributionChart
              data={charts?.severity_distribution ?? []}
              loading={chartsLoading}
            />
            <ProcessingTimeChart
              data={charts?.processing_time_distribution ?? []}
              loading={chartsLoading}
            />
          </div>

          {/* Row 3: Detection Trends (%) & LLM Usage Telemetry Panel */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <DetectionTrendsChart
              data={charts?.detection_trends ?? []}
              loading={chartsLoading}
            />
            <LLMUsageTelemetryCard
              data={
                charts?.llm_usage ?? {
                  total_calls: 0,
                  analyzed_calls: 0,
                  skipped_calls: 0,
                  average_latency_ms: 0,
                  models_breakdown: {},
                }
              }
              loading={chartsLoading}
            />
          </div>

          {/* Row 4: Recent Threats Table (Chart 8) */}
          <RecentThreatsTable
            threats={charts?.recent_threats ?? []}
            loading={chartsLoading}
          />
        </div>
      </div>
    </AppShell>
  )
}
