import { type FC, memo } from 'react'
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
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Bot,
  Clock,
  PieChart as PieIcon,
  Shield,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react'
import type {
  AttackTypeItem,
  DashboardCharts,
  DetectionTrendPoint,
  LatencyDistributionBucket,
  RiskDistributionBucket,
  SeverityDistributionItem,
  ThreatTimelinePoint,
} from '../../entities/dashboard'
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  EmptyState,
  RiskBadge,
  Skeleton,
} from '../../shared/ui'

// Custom tooltip renderer for light mode
interface TooltipPayloadItem {
  name: string
  value: number | string
  color?: string
}

interface CustomTooltipProps {
  active?: boolean
  payload?: TooltipPayloadItem[]
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

// ---------------------------------------------------------------------------
// 1. Threats Over Time Chart
// ---------------------------------------------------------------------------

export const ThreatsOverTimeChart: FC<{
  data: ThreatTimelinePoint[]
  loading?: boolean
}> = memo(({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.total > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<Activity className="h-4 w-4" />}>
          Threats Over Time
          <span className="ml-auto text-xs text-neutral-400 font-normal">
            Last 14 days volume
          </span>
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex flex-col justify-end space-y-2 p-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-4 w-3/4 mx-auto" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<Activity className="h-6 w-6" />}
            title="No threat timeline data"
            description="Process emails to view daily threat patterns."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#dc2626" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorClean" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                <XAxis
                  dataKey="date"
                  tickLine={false}
                  axisLine={{ stroke: '#e5e5e5' }}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  tickFormatter={(val: string) => {
                    const parts = val.split('-')
                    return parts.length === 3 ? `${parts[1]}/${parts[2]}` : val
                  }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomChartTooltip />} />
                <Area
                  type="monotone"
                  dataKey="malicious"
                  name="Malicious"
                  stroke="#dc2626"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorMalicious)"
                />
                <Area
                  type="monotone"
                  dataKey="suspicious"
                  name="Suspicious"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorSuspicious)"
                />
                <Area
                  type="monotone"
                  dataKey="clean"
                  name="Clean"
                  stroke="#22c55e"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorClean)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
})

// ---------------------------------------------------------------------------
// 2. Risk Distribution Chart
// ---------------------------------------------------------------------------

export const RiskDistributionChart: FC<{
  data: RiskDistributionBucket[]
  loading?: boolean
}> = memo(({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.count > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<ShieldAlert className="h-4 w-4" />}>
          Risk Score Distribution
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex flex-col justify-end space-y-2 p-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-4 w-1/2 mx-auto" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<Shield className="h-6 w-6" />}
            title="No risk distribution data"
            description="Score spectrum will populate as emails are analyzed."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                <XAxis
                  dataKey="tier"
                  tickLine={false}
                  axisLine={{ stroke: '#e5e5e5' }}
                  tick={{ fontSize: 10, fill: '#737373' }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomChartTooltip />} />
                <Bar dataKey="count" name="Emails" radius={[6, 6, 0, 0]}>
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color || '#7c3aed'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
})

// ---------------------------------------------------------------------------
// 3. Attack Type Distribution Chart
// ---------------------------------------------------------------------------

const PIE_COLORS = ['#dc2626', '#f97316', '#f59e0b', '#7c3aed', '#14b8a6', '#0284c7']

export const AttackTypeDistributionChart: FC<{
  data: AttackTypeItem[]
  loading?: boolean
}> = ({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.count > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<AlertOctagon className="h-4 w-4" />}>
          Attack Vector Breakdown
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex items-center justify-center p-4">
            <Skeleton className="h-44 w-44 rounded-full" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<AlertOctagon className="h-6 w-6" />}
            title="No attack signals identified"
            description="Specific attack types will register when threats are detected."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="count"
                  nameKey="attack_type"
                >
                  {data.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={PIE_COLORS[index % PIE_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip content={<CustomChartTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  formatter={(val: string) => (
                    <span className="text-2xs text-neutral-600">{val}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// 4. Severity Distribution Chart
// ---------------------------------------------------------------------------

export const SeverityDistributionChart: FC<{
  data: SeverityDistributionItem[]
  loading?: boolean
}> = ({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.count > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<PieIcon className="h-4 w-4" />}>
          Threat Severity Levels
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex items-center justify-center p-4">
            <Skeleton className="h-44 w-44 rounded-full" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<PieIcon className="h-6 w-6" />}
            title="No severity telemetry"
            description="Threat findings will group by severity level."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                  nameKey="severity"
                >
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomChartTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  formatter={(val: string) => (
                    <span className="text-2xs text-neutral-600">{val}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// 5. Analysis Processing Time Chart
// ---------------------------------------------------------------------------

export const ProcessingTimeChart: FC<{
  data: LatencyDistributionBucket[]
  loading?: boolean
}> = ({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.count > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<Clock className="h-4 w-4" />}>
          Pipeline Processing Latency
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex flex-col justify-end space-y-2 p-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-4 w-1/2 mx-auto" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<Clock className="h-6 w-6" />}
            title="No latency data recorded"
            description="Pipeline execution timings will record upon completion."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                <XAxis
                  dataKey="bucket"
                  tickLine={false}
                  axisLine={{ stroke: '#e5e5e5' }}
                  tick={{ fontSize: 10, fill: '#737373' }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomChartTooltip />} />
                <Bar dataKey="count" name="Analyses" fill="#7c3aed" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// 6. LLM Usage Telemetry Panel
// ---------------------------------------------------------------------------

export const LLMUsageTelemetryCard: FC<{
  data: DashboardCharts['llm_usage']
  loading?: boolean
}> = ({ data, loading }) => {
  if (loading) {
    return (
      <Card padding="none" className="overflow-hidden">
        <CardHeader>
          <CardTitle icon={<Bot className="h-4 w-4" />}>Groq LLM Telemetry</CardTitle>
        </CardHeader>
        <CardBody className="p-5 space-y-4">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </CardBody>
      </Card>
    )
  }

  const total = data.total_calls || 0
  const analyzed = data.analyzed_calls || 0
  const skipped = data.skipped_calls || 0
  const avgLat = data.average_latency_ms || 0

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<Bot className="h-4 w-4" />}>
          Groq LLM Usage Telemetry
          <span className="ml-auto">
            <Badge variant="primary">Semantic Layer</Badge>
          </span>
        </CardTitle>
      </CardHeader>
      <CardBody className="p-5 space-y-4">
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="rounded-xl border border-neutral-100 bg-neutral-50/50 p-3">
            <p className="text-2xs font-medium text-neutral-400 uppercase">Total Invocations</p>
            <p className="text-xl font-bold tabular-nums text-neutral-900 mt-0.5">{total}</p>
          </div>
          <div className="rounded-xl border border-violet-100 bg-violet-50/50 p-3">
            <p className="text-2xs font-medium text-violet-600 uppercase">Deep Analyzed</p>
            <p className="text-xl font-bold tabular-nums text-violet-700 mt-0.5">{analyzed}</p>
          </div>
          <div className="rounded-xl border border-neutral-100 bg-neutral-50/50 p-3">
            <p className="text-2xs font-medium text-neutral-400 uppercase">Cost-Bypassed</p>
            <p className="text-xl font-bold tabular-nums text-neutral-600 mt-0.5">{skipped}</p>
          </div>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-neutral-500">Average LLM Roundtrip</span>
            <span className="font-bold tabular-nums text-neutral-800">{avgLat} ms</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-100">
            <div
              className="h-full rounded-full bg-violet-600 transition-all duration-700"
              style={{ width: `${Math.min(100, (avgLat / 2000) * 100)}%` }}
            />
          </div>
        </div>

        {data.models_breakdown && Object.keys(data.models_breakdown).length > 0 && (
          <div className="pt-2 border-t border-neutral-100">
            <p className="text-2xs font-medium text-neutral-400 mb-2 uppercase">Models Utilized</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(data.models_breakdown).map(([model, count]) => (
                <span
                  key={model}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-violet-200 bg-violet-50 px-2 py-1 text-2xs font-mono text-violet-700"
                >
                  <span>{model}</span>
                  <strong className="font-bold">({count})</strong>
                </span>
              ))}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// 7. Detection Trends Chart
// ---------------------------------------------------------------------------

export const DetectionTrendsChart: FC<{
  data: DetectionTrendPoint[]
  loading?: boolean
}> = ({ data, loading }) => {
  const hasData = data && data.length > 0 && data.some((d) => d.volume > 0)

  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<TrendingUp className="h-4 w-4" />}>
          Threat Detection Rate Trend (%)
        </CardTitle>
      </CardHeader>
      <CardBody className="p-4">
        {loading ? (
          <div className="h-64 flex flex-col justify-end space-y-2 p-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-4 w-1/2 mx-auto" />
          </div>
        ) : !hasData ? (
          <EmptyState
            icon={<TrendingUp className="h-6 w-6" />}
            title="No trend data"
            description="Threat rate percentage will graph as volume accumulates."
            className="h-64 border-none bg-transparent"
          />
        ) : (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                <XAxis
                  dataKey="date"
                  tickLine={false}
                  axisLine={{ stroke: '#e5e5e5' }}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  tickFormatter={(val: string) => {
                    const parts = val.split('-')
                    return parts.length === 3 ? `${parts[1]}/${parts[2]}` : val
                  }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: '#737373' }}
                  unit="%"
                />
                <Tooltip content={<CustomChartTooltip />} />
                <Line
                  type="monotone"
                  dataKey="detection_rate_pct"
                  name="Threat Rate %"
                  stroke="#ea580c"
                  strokeWidth={2.5}
                  dot={{ r: 3, fill: '#ea580c' }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// 8. Recent Threats Table
// ---------------------------------------------------------------------------

export const RecentThreatsTable: FC<{
  threats: DashboardCharts['recent_threats']
  loading?: boolean
  onSelectThreat?: (threatId: string) => void
}> = ({ threats, loading, onSelectThreat }) => {
  return (
    <Card padding="none" className="overflow-hidden">
      <CardHeader>
        <CardTitle icon={<ShieldAlert className="h-4 w-4" />}>
          Recent Threats Detected
          <span className="ml-auto">
            <Badge variant="critical">Active Telemetry</Badge>
          </span>
        </CardTitle>
      </CardHeader>
      {loading ? (
        <div className="p-4 space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <Skeleton className="h-8 w-8 rounded-lg" />
              <div className="flex-1 space-y-1">
                <Skeleton className="h-3.5 w-1/3" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              <Skeleton className="h-6 w-16 rounded-full" />
            </div>
          ))}
        </div>
      ) : !threats || threats.length === 0 ? (
        <EmptyState
          icon={<Shield className="h-6 w-6" />}
          title="No recent threat detections"
          description="High-risk and critical incidents will appear here in real-time."
          className="m-4 py-12 border-none bg-transparent"
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-neutral-100 bg-neutral-50/70 text-neutral-500 uppercase font-semibold">
              <tr>
                <th className="px-4 py-2.5">Subject & Threat</th>
                <th className="hidden px-4 py-2.5 sm:table-cell">Sender</th>
                <th className="px-4 py-2.5 text-right">Score</th>
                <th className="px-4 py-2.5">Severity</th>
                <th className="hidden px-4 py-2.5 md:table-cell">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-100">
              {threats.map((t) => (
                <tr
                  key={t.analysis_id}
                  onClick={() => onSelectThreat?.(t.analysis_id)}
                  className="group hover:bg-violet-50/30 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-start gap-2.5">
                      <span className="mt-0.5 text-danger-600 shrink-0">
                        <AlertTriangle className="h-4 w-4" />
                      </span>
                      <div className="min-w-0">
                        <p className="font-semibold text-neutral-900 truncate max-w-xs sm:max-w-md">
                          {t.subject}
                        </p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="rounded bg-coral-100 px-1.5 py-0.2 text-[10px] font-bold text-coral-800">
                            {t.attack_type}
                          </span>
                          {t.has_attachments && (
                            <span className="text-2xs text-neutral-400">📎 Attachment</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="hidden px-4 py-3 sm:table-cell">
                    <p className="text-neutral-700 truncate max-w-[160px]">{t.from_address}</p>
                    <p className="font-mono text-2xs text-neutral-400">{t.from_domain}</p>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className="font-bold tabular-nums text-danger-600 text-sm">
                      {t.risk_score}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge
                      level={
                        t.risk_level.toLowerCase() === 'critical'
                          ? 'critical'
                          : t.risk_level.toLowerCase() === 'high'
                            ? 'high'
                            : 'medium'
                      }
                    />
                  </td>
                  <td className="hidden px-4 py-3 text-neutral-400 md:table-cell">
                    {new Date(t.received_at).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
