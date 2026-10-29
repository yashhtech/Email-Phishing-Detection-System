import { type FC, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  BarChart3,
  Bot,
  Clock,
  Cpu,
  Download,
  Globe,
  LineChart as LineChartIcon,
  PieChart as PieIcon,
  RefreshCw,
  Shield,
  Target,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { analyticsApi } from '../shared/api/analytics.api'
import type {
  AnalyticsOverview,
  DateRangePreset,
  SenderDomainPoint,
} from '../entities/analytics'
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  EmptyState,
  Skeleton,
} from '../shared/ui'
import { AppShell } from '../shared/layout/AppShell'
import { cn } from '../shared/lib/utils'

// ---------------------------------------------------------------------------
// Strict Color Token Rules:
// - critical → bg-danger-50 text-danger-700 border-danger-200 (red)
// - high → bg-coral-50 text-coral-700 border-coral-200 (orange)
// - medium → bg-warning-50 text-warning-700 border-warning-200 (amber)
// - low/safe → bg-success-50 text-success-700 border-success-200 (green)
// - AI/LLM content → bg-violet-50 text-violet-700 border-violet-200 (purple)
// - technical/auth signals → bg-teal-50 text-teal-700 border-teal-200 (teal)
// ---------------------------------------------------------------------------

const PRESETS: { id: DateRangePreset; label: string }[] = [
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
  { id: '30d', label: '30d' },
  { id: '90d', label: '90d' },
]

const RISK_COLOR_MAP: Record<string, { fill: string; badge: string }> = {
  critical: {
    fill: '#ef4444',
    badge: 'bg-danger-50 text-danger-700 border-danger-200',
  },
  high: {
    fill: '#f97316',
    badge: 'bg-coral-50 text-coral-700 border-coral-200',
  },
  medium: {
    fill: '#f59e0b',
    badge: 'bg-warning-50 text-warning-700 border-warning-200',
  },
  low: {
    fill: '#22c55e',
    badge: 'bg-success-50 text-success-700 border-success-200',
  },
  safe: {
    fill: '#22c55e',
    badge: 'bg-success-50 text-success-700 border-success-200',
  },
}

function formatPercent(value: number): string {
  const normalized = value <= 1 ? value * 100 : value
  return `${normalized.toFixed(1)}%`
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ name: string; value: number | string; color?: string }>
  label?: string
}

const CustomChartTooltip: FC<CustomTooltipProps> = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded-xl border border-neutral-200 bg-white p-3 shadow-md text-xs">
        {label && <p className="font-semibold text-neutral-800 mb-1.5">{label}</p>}
        <div className="space-y-1">
          {payload.map((item, idx) => (
            <div key={idx} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-neutral-600">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: item.color || '#7c3aed' }}
                />
                {item.name}:
              </span>
              <span className="font-bold tabular-nums text-neutral-900">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    )
  }
  return null
}

export const AnalyticsPage: FC = () => {
  const [preset, setPreset] = useState<DateRangePreset>('7d')

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery<AnalyticsOverview>({
    queryKey: ['analytics', 'overview', preset],
    queryFn: () => analyticsApi.getOverview({ preset }),
    staleTime: 60_000,
  })

  const exportUrl = analyticsApi.getExportUrl({ preset })

  return (
    <AppShell>
      <div className="space-y-6 pb-12">
        {/* Top Header & Global Controls */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-neutral-900">
                Security Analytics
              </h1>
              <span className="rounded-full bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 text-2xs font-semibold">
                Live Telemetry
              </span>
            </div>
            <p className="text-xs sm:text-sm text-neutral-500 mt-1">
              Deep-dive security telemetry, model efficacy, threat trends, and detection analytics.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Preset Selector */}
            <div
              className="inline-flex rounded-xl border border-neutral-200 bg-white p-1 shadow-xs"
              role="group"
              aria-label="Date range preset"
            >
              {PRESETS.map((item) => {
                const isActive = preset === item.id
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setPreset(item.id)}
                    className={cn(
                      'rounded-lg px-3 py-1.5 text-xs font-semibold transition-all duration-150',
                      isActive
                        ? 'bg-violet-600 text-white shadow-xs'
                        : 'text-neutral-600 hover:text-neutral-900 hover:bg-neutral-100',
                    )}
                    aria-pressed={isActive}
                  >
                    {item.label}
                  </button>
                )
              })}
            </div>

            {/* Refresh Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isFetching}
              title="Refresh Analytics"
              leftIcon={<RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} />}
            >
              Sync
            </Button>

            {/* Export CSV link */}
            <a
              href={exportUrl}
              download={`threat-analytics-${preset}.csv`}
              className="inline-flex items-center justify-center gap-2 font-semibold transition-all duration-150 rounded-xl border border-neutral-200 bg-white text-neutral-700 shadow-xs hover:border-neutral-300 hover:bg-neutral-50 h-8 px-3.5 text-xs"
            >
              <Download className="h-3.5 w-3.5 text-neutral-500" />
              Export CSV
            </a>
          </div>
        </div>

        {/* Global Error Banner */}
        {isError && (
          <Alert variant="error" title="Failed to load analytics">
            {error instanceof Error ? error.message : 'Unknown error occurred while fetching analytics data.'}
            <div className="mt-2">
              <Button size="xs" variant="outline" onClick={() => refetch()}>
                Try again
              </Button>
            </div>
          </Alert>
        )}

        {/* ================================================================= */}
        {/* ROW 1: Threat Trends & Detection Rate                             */}
        {/* ================================================================= */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Section: Threat Trends */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<Activity className="h-4 w-4" />}>
                Threat Trends
              </CardTitle>
              <span className="text-2xs text-neutral-400 font-normal">
                Threats vs Clean over time
              </span>
            </CardHeader>
            <CardBody className="p-4">
              {isLoading ? (
                <div className="h-64 flex flex-col justify-end space-y-2 p-4">
                  <Skeleton className="h-44 w-full" />
                  <Skeleton className="h-4 w-3/4 mx-auto" />
                </div>
              ) : !data?.threat_trends?.length ? (
                <EmptyState
                  icon={<Activity className="h-6 w-6" />}
                  title="No threat trend data"
                  description="No timeline events recorded in the selected preset."
                  className="h-64 border-none bg-transparent"
                />
              ) : (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={data.threat_trends}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="colorClean" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#22c55e" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#22c55e" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis
                        dataKey="date"
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip content={<CustomChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                      <Area
                        type="monotone"
                        dataKey="threats"
                        name="Threats"
                        stroke="#ef4444"
                        strokeWidth={2}
                        fill="url(#colorThreats)"
                      />
                      <Area
                        type="monotone"
                        dataKey="clean"
                        name="Clean"
                        stroke="#22c55e"
                        strokeWidth={2}
                        fill="url(#colorClean)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Section: Detection Rate */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<LineChartIcon className="h-4 w-4" />}>
                Detection Rate
              </CardTitle>
              <span className="text-2xs text-neutral-400 font-normal">
                % detected over time
              </span>
            </CardHeader>
            <CardBody className="p-4">
              {isLoading ? (
                <div className="h-64 flex flex-col justify-end space-y-2 p-4">
                  <Skeleton className="h-44 w-full" />
                  <Skeleton className="h-4 w-3/4 mx-auto" />
                </div>
              ) : !data?.detection_rates?.length ? (
                <EmptyState
                  icon={<LineChartIcon className="h-6 w-6" />}
                  title="No detection rate data"
                  description="Detection rate history is not available for this period."
                  className="h-64 border-none bg-transparent"
                />
              ) : (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart
                      data={data.detection_rates}
                      margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis
                        dataKey="date"
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                        unit="%"
                        domain={[0, 100]}
                      />
                      <Tooltip content={<CustomChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                      <Line
                        type="monotone"
                        dataKey="detection_rate"
                        name="Detection Rate (%)"
                        stroke="#7c3aed"
                        strokeWidth={2.5}
                        dot={{ r: 3, fill: '#7c3aed' }}
                        activeDot={{ r: 5 }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardBody>
          </Card>
        </div>

        {/* ================================================================= */}
        {/* ROW 2: Attack Type Distribution & Risk Distribution               */}
        {/* ================================================================= */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Section: Attack Type Distribution */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<BarChart3 className="h-4 w-4" />}>
                Attack Type Distribution
              </CardTitle>
            </CardHeader>
            <CardBody className="p-4">
              {isLoading ? (
                <div className="h-64 flex flex-col justify-end space-y-2 p-4">
                  <Skeleton className="h-44 w-full" />
                  <Skeleton className="h-4 w-3/4 mx-auto" />
                </div>
              ) : !data?.attack_types?.length ? (
                <EmptyState
                  icon={<BarChart3 className="h-6 w-6" />}
                  title="No attack type data"
                  description="No categorized attacks detected within the selected range."
                  className="h-64 border-none bg-transparent"
                />
              ) : (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={data.attack_types}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis
                        dataKey="attack_type"
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        stroke="#a3a3a3"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip content={<CustomChartTooltip />} />
                      <Bar dataKey="count" name="Count" fill="#7c3aed" radius={[4, 4, 0, 0]}>
                        {data.attack_types.map((_, index) => {
                          const colors = ['#dc2626', '#ea580c', '#7c3aed', '#0d9488', '#f59e0b']
                          return <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                        })}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Section: Risk Distribution */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<PieIcon className="h-4 w-4" />}>
                Risk Distribution
              </CardTitle>
            </CardHeader>
            <CardBody className="p-4">
              {isLoading ? (
                <div className="h-64 flex flex-col justify-end space-y-2 p-4">
                  <Skeleton className="h-44 w-full" />
                  <Skeleton className="h-4 w-3/4 mx-auto" />
                </div>
              ) : !data?.risk_distribution?.length ? (
                <EmptyState
                  icon={<PieIcon className="h-6 w-6" />}
                  title="No risk distribution data"
                  description="No assessed risk metrics available."
                  className="h-64 border-none bg-transparent"
                />
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 items-center gap-4 h-64">
                  <div className="h-full w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={data.risk_distribution}
                          dataKey="count"
                          nameKey="level"
                          cx="50%"
                          cy="50%"
                          outerRadius={75}
                          innerRadius={45}
                          paddingAngle={3}
                        >
                          {data.risk_distribution.map((entry, index) => {
                            const lvl = entry.level.toLowerCase()
                            const color =
                              entry.color ||
                              RISK_COLOR_MAP[lvl]?.fill ||
                              '#7c3aed'
                            return <Cell key={`pie-cell-${index}`} fill={color} />
                          })}
                        </Pie>
                        <Tooltip content={<CustomChartTooltip />} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  {/* Legend */}
                  <div className="space-y-2 overflow-y-auto max-h-56 pr-2">
                    {data.risk_distribution.map((item, idx) => {
                      const lvl = item.level.toLowerCase()
                      const badgeClass =
                        RISK_COLOR_MAP[lvl]?.badge ||
                        'bg-neutral-100 text-neutral-700 border-neutral-200'
                      return (
                        <div
                          key={idx}
                          className="flex items-center justify-between text-xs p-1.5 rounded-lg hover:bg-neutral-50 transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <span
                              className="h-2.5 w-2.5 rounded-full"
                              style={{
                                backgroundColor:
                                  item.color ||
                                  RISK_COLOR_MAP[lvl]?.fill ||
                                  '#7c3aed',
                              }}
                            />
                            <span className="font-medium text-neutral-700 capitalize">
                              {item.level}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="font-semibold tabular-nums text-neutral-900">
                              {item.count}
                            </span>
                            {item.percentage !== undefined && (
                              <span
                                className={cn(
                                  'rounded-md px-1.5 py-0.5 text-2xs font-semibold border',
                                  badgeClass,
                                )}
                              >
                                {formatPercent(item.percentage)}
                              </span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </CardBody>
          </Card>
        </div>

        {/* ================================================================= */}
        {/* ROW 3: Top Sender Domains Table                                   */}
        {/* ================================================================= */}
        <Card padding="none" className="overflow-hidden">
          <CardHeader>
            <CardTitle icon={<Globe className="h-4 w-4" />}>
              Top Sender Domains
            </CardTitle>
            <span className="text-2xs text-neutral-400 font-normal">
              High-volume domains ranked by threat frequency
            </span>
          </CardHeader>
          <CardBody className="p-0">
            {isLoading ? (
              <div className="p-5 space-y-3">
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
              </div>
            ) : !data?.top_sender_domains?.length ? (
              <EmptyState
                icon={<Globe className="h-6 w-6" />}
                title="No sender domains recorded"
                description="Sender domain analysis will appear as incoming emails are ingested."
                className="py-12 border-none bg-transparent"
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-neutral-100 bg-neutral-50/75 text-neutral-500 font-semibold uppercase tracking-wider text-2xs">
                    <tr>
                      <th className="py-3 px-5">Domain</th>
                      <th className="py-3 px-5 text-right">Total Emails</th>
                      <th className="py-3 px-5 text-right">Threats Detected</th>
                      <th className="py-3 px-5 text-right">Threat Rate</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-100 font-medium">
                    {data.top_sender_domains.map((row: SenderDomainPoint, idx: number) => {
                      const rate = row.threat_rate <= 1 ? row.threat_rate * 100 : row.threat_rate
                      const isHighThreat = rate >= 50
                      const isMediumThreat = rate >= 20 && rate < 50
                      const badgeClass = isHighThreat
                        ? 'bg-danger-50 text-danger-700 border-danger-200'
                        : isMediumThreat
                          ? 'bg-warning-50 text-warning-700 border-warning-200'
                          : 'bg-success-50 text-success-700 border-success-200'

                      return (
                        <tr key={idx} className="hover:bg-neutral-50/50 transition-colors">
                          <td className="py-3.5 px-5 font-mono text-neutral-800 flex items-center gap-2">
                            <span className="h-1.5 w-1.5 rounded-full bg-neutral-400" />
                            {row.domain}
                          </td>
                          <td className="py-3.5 px-5 text-right tabular-nums text-neutral-700">
                            {row.total.toLocaleString()}
                          </td>
                          <td className="py-3.5 px-5 text-right tabular-nums font-semibold text-danger-600">
                            {row.threats.toLocaleString()}
                          </td>
                          <td className="py-3.5 px-5 text-right">
                            <span
                              className={cn(
                                'inline-flex items-center rounded-md px-2 py-0.5 text-2xs font-semibold border',
                                badgeClass,
                              )}
                            >
                              {rate.toFixed(1)}%
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>

        {/* ================================================================= */}
        {/* ROW 4: ML Performance & LLM Utilization Cards                     */}
        {/* ================================================================= */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Section: ML Performance */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<Cpu className="h-4 w-4" />}>
                ML Performance
              </CardTitle>
              <span className="text-2xs text-neutral-400 font-normal">
                Local feature & classification engine
              </span>
            </CardHeader>
            <CardBody className="p-5 space-y-5">
              {isLoading ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-3">
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-16 w-full" />
                  </div>
                  <Skeleton className="h-20 w-full" />
                </div>
              ) : !data?.ml_performance ? (
                <EmptyState
                  icon={<Cpu className="h-6 w-6" />}
                  title="No ML telemetry"
                  description="Telemetry not available for local ML model."
                  className="py-8 border-none bg-transparent"
                />
              ) : (
                <>
                  <div className="grid grid-cols-3 gap-3 text-center">
                    <div className="p-3 rounded-xl border border-neutral-200 bg-neutral-50/50">
                      <p className="text-2xs font-semibold uppercase text-neutral-500">
                        Predictions
                      </p>
                      <p className="text-lg font-bold tabular-nums text-neutral-900 mt-1">
                        {data.ml_performance.total_predictions.toLocaleString()}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-success-200 bg-success-50 text-success-700">
                      <p className="text-2xs font-semibold uppercase">
                        Avg Confidence
                      </p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {formatPercent(data.ml_performance.avg_confidence)}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-teal-200 bg-teal-50 text-teal-700">
                      <p className="text-2xs font-semibold uppercase">
                        Avg Latency
                      </p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {data.ml_performance.avg_latency_ms.toFixed(1)} ms
                      </p>
                    </div>
                  </div>

                  {/* Label breakdown */}
                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      Predicted Labels Breakdown
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(data.ml_performance.label_breakdown || {}).map(
                        ([label, count]) => (
                          <div
                            key={label}
                            className="flex items-center gap-1.5 rounded-lg border border-neutral-200 bg-white px-2.5 py-1 text-xs"
                          >
                            <span className="font-medium text-neutral-600 capitalize">
                              {label}:
                            </span>
                            <span className="font-bold text-neutral-900 tabular-nums">
                              {count.toLocaleString()}
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>

                  {/* Probabilities / Confidence bins */}
                  {data.ml_performance.probabilities && (
                    <div>
                      <p className="text-xs font-semibold text-neutral-700 mb-2">
                        Confidence Probabilities
                      </p>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        {Object.entries(data.ml_performance.probabilities).map(
                          ([bin, count]) => (
                            <div
                              key={bin}
                              className="rounded-lg border border-neutral-150 p-2 text-center bg-neutral-50/30"
                            >
                              <p className="text-2xs text-neutral-500 font-mono">{bin}</p>
                              <p className="text-xs font-bold text-neutral-800 mt-0.5">
                                {count.toLocaleString()}
                              </p>
                            </div>
                          ),
                        )}
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardBody>
          </Card>

          {/* Section: LLM Utilization */}
          {/* AI/LLM content strictly styled: bg-violet-50 text-violet-700 border-violet-200 */}
          <Card padding="none" className="overflow-hidden border-violet-200">
            <CardHeader className="bg-violet-50/60 border-violet-100">
              <CardTitle icon={<Bot className="h-4 w-4 text-violet-600" />}>
                LLM Utilization
              </CardTitle>
              <span className="rounded-full bg-violet-100 text-violet-700 border border-violet-200 px-2 py-0.5 text-2xs font-semibold">
                Reasoning Telemetry
              </span>
            </CardHeader>
            <CardBody className="p-5 space-y-5 bg-gradient-to-b from-violet-50/20 to-transparent">
              {isLoading ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-3">
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-16 w-full" />
                    <Skeleton className="h-16 w-full" />
                  </div>
                  <Skeleton className="h-20 w-full" />
                </div>
              ) : !data?.llm_utilization ? (
                <EmptyState
                  icon={<Bot className="h-6 w-6" />}
                  title="No LLM telemetry"
                  description="Telemetry not available for LLM reasoning layer."
                  className="py-8 border-none bg-transparent"
                />
              ) : (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    <div className="p-3 rounded-xl border border-violet-200 bg-violet-50 text-violet-700">
                      <p className="text-2xs font-semibold uppercase">
                        Utilization
                      </p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {formatPercent(data.llm_utilization.utilization_rate)}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-neutral-200 bg-white">
                      <p className="text-2xs font-semibold uppercase text-neutral-500">
                        Invocations
                      </p>
                      <p className="text-lg font-bold tabular-nums text-neutral-900 mt-1">
                        {data.llm_utilization.total_invocations.toLocaleString()}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-danger-200 bg-danger-50 text-danger-700">
                      <p className="text-2xs font-semibold uppercase">
                        Safety Failures
                      </p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {data.llm_utilization.safety_failures}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-violet-200 bg-violet-50 text-violet-700">
                      <p className="text-2xs font-semibold uppercase">
                        Avg Latency
                      </p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {data.llm_utilization.avg_latency_ms.toFixed(0)} ms
                      </p>
                    </div>
                  </div>

                  {data.llm_utilization.avg_confidence !== undefined && (
                    <div className="flex items-center justify-between p-3 rounded-xl bg-violet-50/50 border border-violet-200 text-xs">
                      <span className="font-medium text-violet-800">
                        Average Synthesis Confidence:
                      </span>
                      <span className="font-bold text-violet-900 tabular-nums">
                        {formatPercent(data.llm_utilization.avg_confidence)}
                      </span>
                    </div>
                  )}

                  {/* Model Breakdown */}
                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      Model Invocations Breakdown
                    </p>
                    <div className="space-y-2">
                      {Object.entries(data.llm_utilization.model_breakdown || {}).map(
                        ([modelName, calls]) => (
                          <div
                            key={modelName}
                            className="flex items-center justify-between p-2.5 rounded-xl border border-violet-150 bg-white text-xs shadow-2xs"
                          >
                            <span className="font-mono text-neutral-800 font-medium">
                              {modelName}
                            </span>
                            <span className="rounded-md bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 text-2xs font-bold tabular-nums">
                              {calls.toLocaleString()} calls
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                </>
              )}
            </CardBody>
          </Card>
        </div>

        {/* ================================================================= */}
        {/* ROW 5: Processing Latency & Threat Intelligence Cards             */}
        {/* ================================================================= */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Section: Processing Latency */}
          {/* technical/auth signals strictly styled: bg-teal-50 text-teal-700 border-teal-200 */}
          <Card padding="none" className="overflow-hidden border-teal-200">
            <CardHeader className="bg-teal-50/60 border-teal-100">
              <CardTitle icon={<Clock className="h-4 w-4 text-teal-600" />}>
                Processing Latency
              </CardTitle>
              <span className="rounded-full bg-teal-100 text-teal-700 border border-teal-200 px-2 py-0.5 text-2xs font-semibold">
                Pipeline SLAs
              </span>
            </CardHeader>
            <CardBody className="p-5 space-y-5 bg-gradient-to-b from-teal-50/20 to-transparent">
              {isLoading ? (
                <div className="grid grid-cols-3 gap-3">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ) : !data?.processing_latency ? (
                <EmptyState
                  icon={<Clock className="h-6 w-6" />}
                  title="No latency data"
                  description="Pipeline processing latency is not available."
                  className="py-8 border-none bg-transparent"
                />
              ) : (
                <>
                  <div className="grid grid-cols-3 gap-3 text-center">
                    <div className="p-3 rounded-xl border border-teal-200 bg-teal-50 text-teal-700">
                      <p className="text-2xs font-semibold uppercase">Avg Latency</p>
                      <p className="text-lg font-bold tabular-nums mt-1">
                        {data.processing_latency.avg_ms.toFixed(1)} ms
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-neutral-200 bg-white">
                      <p className="text-2xs font-semibold uppercase text-neutral-500">Min Latency</p>
                      <p className="text-lg font-bold tabular-nums text-neutral-900 mt-1">
                        {data.processing_latency.min_ms.toFixed(1)} ms
                      </p>
                    </div>
                    <div className="p-3 rounded-xl border border-neutral-200 bg-white">
                      <p className="text-2xs font-semibold uppercase text-neutral-500">Max Latency</p>
                      <p className="text-lg font-bold tabular-nums text-neutral-900 mt-1">
                        {data.processing_latency.max_ms.toFixed(1)} ms
                      </p>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      Latency Percentiles
                    </p>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      <div className="p-2.5 rounded-lg border border-neutral-200 bg-white">
                        <span className="text-2xs font-mono font-bold text-neutral-500">P50 (Median)</span>
                        <p className="text-sm font-bold text-neutral-900 mt-0.5">
                          {data.processing_latency.p50_ms.toFixed(1)} ms
                        </p>
                      </div>
                      <div className="p-2.5 rounded-lg border border-neutral-200 bg-white">
                        <span className="text-2xs font-mono font-bold text-neutral-500">P90</span>
                        <p className="text-sm font-bold text-neutral-900 mt-0.5">
                          {data.processing_latency.p90_ms.toFixed(1)} ms
                        </p>
                      </div>
                      <div className="p-2.5 rounded-lg border border-warning-200 bg-warning-50 text-warning-700">
                        <span className="text-2xs font-mono font-bold">P99 (Tail)</span>
                        <p className="text-sm font-bold mt-0.5">
                          {data.processing_latency.p99_ms.toFixed(1)} ms
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </CardBody>
          </Card>

          {/* Section: Threat Intelligence */}
          <Card padding="none" className="overflow-hidden">
            <CardHeader>
              <CardTitle icon={<Shield className="h-4 w-4" />}>
                Threat Intelligence
              </CardTitle>
              <span className="text-2xs text-neutral-400 font-normal">
                Multi-provider feed queries & verdicts
              </span>
            </CardHeader>
            <CardBody className="p-5 space-y-5">
              {isLoading ? (
                <div className="space-y-3">
                  <Skeleton className="h-20 w-full" />
                  <Skeleton className="h-20 w-full" />
                </div>
              ) : !data?.threat_intel ? (
                <EmptyState
                  icon={<Shield className="h-6 w-6" />}
                  title="No Threat Intel data"
                  description="Threat intel usage metrics have not been generated."
                  className="py-8 border-none bg-transparent"
                />
              ) : (
                <>
                  {/* Verdicts breakdown */}
                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      External Intel Verdicts
                    </p>
                    <div className="grid grid-cols-3 gap-2">
                      {Object.entries(data.threat_intel.verdicts_breakdown || {}).map(
                        ([verdict, count]) => {
                          const v = verdict.toLowerCase()
                          const badge =
                            v === 'malicious'
                              ? 'bg-danger-50 text-danger-700 border-danger-200'
                              : v === 'suspicious'
                                ? 'bg-warning-50 text-warning-700 border-warning-200'
                                : 'bg-success-50 text-success-700 border-success-200'
                          return (
                            <div
                              key={verdict}
                              className={cn(
                                'rounded-xl p-2.5 text-center border font-semibold',
                                badge,
                              )}
                            >
                              <p className="text-2xs uppercase capitalize">{verdict}</p>
                              <p className="text-base font-bold tabular-nums mt-0.5">
                                {count.toLocaleString()}
                              </p>
                            </div>
                          )
                        },
                      )}
                    </div>
                  </div>

                  {/* Queries by provider */}
                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      Queries by Provider
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(data.threat_intel.queries_by_provider || {}).map(
                        ([provider, count]) => (
                          <div
                            key={provider}
                            className="flex items-center gap-1.5 rounded-lg border border-neutral-200 bg-neutral-50 px-2.5 py-1 text-xs"
                          >
                            <span className="font-semibold text-neutral-700">{provider}:</span>
                            <span className="font-bold text-neutral-900 tabular-nums">
                              {count.toLocaleString()}
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>

                  {/* Indicator types */}
                  <div>
                    <p className="text-xs font-semibold text-neutral-700 mb-2">
                      Queried Indicator Types
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(data.threat_intel.indicator_types || {}).map(
                        ([type, count]) => (
                          <div
                            key={type}
                            className="flex items-center gap-1.5 rounded-lg border border-teal-200 bg-teal-50 px-2.5 py-1 text-xs text-teal-800"
                          >
                            <span className="uppercase text-2xs font-bold">{type}:</span>
                            <span className="font-bold tabular-nums">{count.toLocaleString()}</span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                </>
              )}
            </CardBody>
          </Card>
        </div>

        {/* ================================================================= */}
        {/* ROW 6: False Positive Tracking Card                               */}
        {/* ================================================================= */}
        <Card padding="none" className="overflow-hidden">
          <CardHeader>
            <CardTitle icon={<Target className="h-4 w-4" />}>
              False Positive Tracking
            </CardTitle>
            <span className="text-2xs text-neutral-400 font-normal">
              Analyst feedback & verification efficacy
            </span>
          </CardHeader>
          <CardBody className="p-5">
            {isLoading ? (
              <div className="grid grid-cols-4 gap-3">
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
              </div>
            ) : !data?.false_positives || data.false_positives.data_available === false ? (
              <EmptyState
                icon={<Target className="h-6 w-6 text-neutral-400" />}
                title="No labeled feedback data"
                description="Ground truth labels have not been submitted yet. Report false positives or submit analyst reviews to enable precision and recall metrics."
                className="py-12 border-none bg-transparent"
              />
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
                  <div className="p-3.5 rounded-xl border border-neutral-200 bg-neutral-50/50">
                    <p className="text-2xs font-semibold uppercase text-neutral-500">
                      Labeled Data Count
                    </p>
                    <p className="text-xl font-bold tabular-nums text-neutral-900 mt-1">
                      {data.false_positives.labeled_count?.toLocaleString() ?? 0}
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl border border-danger-200 bg-danger-50 text-danger-700">
                    <p className="text-2xs font-semibold uppercase">
                      False Positives (FPs)
                    </p>
                    <p className="text-xl font-bold tabular-nums mt-1">
                      {data.false_positives.false_positives ?? 0}
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl border border-warning-200 bg-warning-50 text-warning-700">
                    <p className="text-2xs font-semibold uppercase">
                      False Negatives (FNs)
                    </p>
                    <p className="text-xl font-bold tabular-nums mt-1">
                      {data.false_positives.false_negatives ?? 0}
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl border border-coral-200 bg-coral-50 text-coral-700">
                    <p className="text-2xs font-semibold uppercase">
                      FP Rate
                    </p>
                    <p className="text-xl font-bold tabular-nums mt-1">
                      {data.false_positives.false_positive_rate !== undefined
                        ? formatPercent(data.false_positives.false_positive_rate)
                        : '0.0%'}
                    </p>
                  </div>
                </div>

                {(data.false_positives.precision !== undefined ||
                  data.false_positives.recall !== undefined ||
                  data.false_positives.accuracy !== undefined) && (
                  <div className="flex flex-wrap items-center justify-around gap-4 p-3 rounded-xl border border-neutral-200 bg-white text-xs">
                    {data.false_positives.precision !== undefined && (
                      <div>
                        <span className="text-neutral-500">Precision: </span>
                        <span className="font-bold text-neutral-900 tabular-nums">
                          {formatPercent(data.false_positives.precision)}
                        </span>
                      </div>
                    )}
                    {data.false_positives.recall !== undefined && (
                      <div>
                        <span className="text-neutral-500">Recall: </span>
                        <span className="font-bold text-neutral-900 tabular-nums">
                          {formatPercent(data.false_positives.recall)}
                        </span>
                      </div>
                    )}
                    {data.false_positives.accuracy !== undefined && (
                      <div>
                        <span className="text-neutral-500">Accuracy: </span>
                        <span className="font-bold text-neutral-900 tabular-nums">
                          {formatPercent(data.false_positives.accuracy)}
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </AppShell>
  )
}
