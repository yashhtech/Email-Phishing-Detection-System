import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  AlertOctagon,
  CheckCircle,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
} from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import { threatsApi, type ThreatSignalItem } from '../shared/api/threats.api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function severityClasses(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-danger-50 text-danger-700 border-danger-200'
    case 'high':
      return 'bg-coral-50 text-coral-700 border-coral-200'
    case 'medium':
      return 'bg-warning-50 text-warning-700 border-warning-200'
    case 'low':
      return 'bg-success-50 text-success-700 border-success-200'
    default:
      return 'bg-neutral-50 text-neutral-600 border-neutral-200'
  }
}

function severityIcon(severity: string) {
  switch (severity) {
    case 'critical':
      return <AlertOctagon className="h-3.5 w-3.5 text-danger-600" />
    case 'high':
      return <AlertTriangle className="h-3.5 w-3.5 text-coral-600" />
    case 'medium':
      return <AlertTriangle className="h-3.5 w-3.5 text-warning-600" />
    default:
      return <CheckCircle className="h-3.5 w-3.5 text-success-600" />
  }
}

function SeverityCountCard({
  label,
  count,
  severity,
}: {
  label: string
  count: number
  severity: string
}) {
  const cls = severityClasses(severity)
  return (
    <div
      className={`flex flex-col items-center justify-center p-4 rounded-xl border ${cls} min-w-[90px] shadow-sm`}
    >
      <span className="text-2xl font-bold tabular-nums">{count}</span>
      <span className="text-xs font-semibold capitalize mt-0.5">{label}</span>
    </div>
  )
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-neutral-100 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full bg-violet-500"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-neutral-400 tabular-nums w-7 text-right">
        {pct}%
      </span>
    </div>
  )
}

function ThreatRow({
  signal,
  onViewAnalysis,
}: {
  signal: ThreatSignalItem
  onViewAnalysis: () => void
}) {
  const cls = severityClasses(signal.severity)
  return (
    <tr className="hover:bg-neutral-50 transition-colors group">
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg text-xs font-semibold border capitalize ${cls}`}
        >
          {severityIcon(signal.severity)}
          {signal.severity}
        </span>
      </td>
      <td className="px-4 py-3">
        <div>
          <p className="text-sm font-medium text-neutral-800 line-clamp-1">
            {signal.title}
          </p>
          <p className="text-xs text-neutral-400 line-clamp-1 mt-0.5">
            {signal.description}
          </p>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className="text-xs font-medium capitalize bg-teal-50 text-teal-700 border border-teal-100 px-2 py-0.5 rounded-lg">
          {signal.attack_type.replace(/_/g, ' ')}
        </span>
      </td>
      <td className="px-4 py-3">
        {signal.indicator_value ? (
          <code className="text-xs font-mono text-teal-800 bg-teal-50 border border-teal-100 rounded px-1.5 py-0.5 max-w-[200px] block truncate">
            {signal.indicator_value}
          </code>
        ) : (
          <span className="text-xs text-neutral-300">—</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-neutral-500 capitalize">{signal.source}</span>
      </td>
      <td className="px-4 py-3 w-32">
        <ConfidenceBar value={signal.confidence} />
      </td>
      <td className="px-4 py-3">
        <span className="text-xs text-neutral-400">
          {signal.created_at ? new Date(signal.created_at).toLocaleDateString() : '—'}
        </span>
      </td>
      <td className="px-4 py-3 text-right">
        <button
          onClick={onViewAnalysis}
          className="opacity-0 group-hover:opacity-100 inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-violet-700 bg-violet-50 border border-violet-200 rounded-lg hover:bg-violet-100 transition-all cursor-pointer"
        >
          <ExternalLink className="h-3 w-3" />
          View
        </button>
      </td>
    </tr>
  )
}

export function ThreatIntelPage() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('')

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['threats', page, severityFilter, attackTypeFilter],
    queryFn: () =>
      threatsApi.list({
        page,
        page_size: 20,
        ...(severityFilter ? { severity: severityFilter } : {}),
        ...(attackTypeFilter ? { attack_type: attackTypeFilter } : {}),
      }),
    staleTime: 30_000,
  })

  const totalPages = data ? Math.max(1, Math.ceil(data.total / 20)) : 1
  const severityCounts = data?.severity_counts ?? {}
  const attackTypeCounts = data?.attack_type_counts ?? {}

  const sortedAttackTypes = Object.entries(attackTypeCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)

  return (
    <AppShell>
      <div className="px-6 py-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-teal-50 rounded-xl border border-teal-100">
              <Shield className="h-5 w-5 text-teal-600" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-neutral-900">
                Threat Intelligence
              </h1>
              <p className="text-sm text-neutral-500">
                {data
                  ? `${data.total.toLocaleString()} threat indicators & signals recorded`
                  : 'Analyzing security telemetry...'}
              </p>
            </div>
          </div>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm text-neutral-600 bg-white border border-neutral-200 rounded-xl hover:bg-neutral-50 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Severity Metric Cards */}
        <div className="flex flex-wrap gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => {
                setSeverityFilter(severityFilter === sev ? '' : sev)
                setPage(1)
              }}
              className={`transition-all cursor-pointer rounded-xl ${
                severityFilter === sev ? 'ring-2 ring-violet-500 ring-offset-2' : ''
              }`}
            >
              <SeverityCountCard
                label={sev}
                count={severityCounts[sev] ?? 0}
                severity={sev}
              />
            </button>
          ))}
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap gap-3 items-center bg-white border border-neutral-150 rounded-2xl p-4 shadow-card">
          <Filter className="h-4 w-4 text-neutral-400" />
          <span className="text-sm font-semibold text-neutral-600">Filter Signals:</span>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value)
              setPage(1)
            }}
            className="text-sm border border-neutral-200 rounded-lg px-3 py-1.5 bg-white text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-300"
          >
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s} className="capitalize">
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>

          <select
            value={attackTypeFilter}
            onChange={(e) => {
              setAttackTypeFilter(e.target.value)
              setPage(1)
            }}
            className="text-sm border border-neutral-200 rounded-lg px-3 py-1.5 bg-white text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-300"
          >
            <option value="">All Attack Types</option>
            {sortedAttackTypes.map(([at]) => (
              <option key={at} value={at}>
                {at.replace(/_/g, ' ')}
              </option>
            ))}
          </select>

          {(severityFilter || attackTypeFilter) && (
            <button
              onClick={() => {
                setSeverityFilter('')
                setAttackTypeFilter('')
                setPage(1)
              }}
              className="text-xs text-violet-600 hover:text-violet-800 font-medium underline ml-auto cursor-pointer"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Signals Table */}
        <div className="bg-white border border-neutral-150 rounded-2xl shadow-card overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-48">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-violet-500 border-t-transparent" />
            </div>
          ) : isError ? (
            <div className="flex flex-col items-center justify-center h-48 gap-3">
              <AlertTriangle className="h-8 w-8 text-danger-400" />
              <p className="text-sm text-neutral-500">
                Failed to load threat intelligence records
              </p>
              <button
                onClick={() => refetch()}
                className="text-sm text-violet-600 underline font-medium cursor-pointer"
              >
                Retry
              </button>
            </div>
          ) : data?.items.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 gap-3">
              <Shield className="h-10 w-10 text-success-400" />
              <p className="text-base font-semibold text-neutral-700">
                No threat indicators found
              </p>
              <p className="text-sm text-neutral-400">
                {severityFilter || attackTypeFilter
                  ? 'Try clearing active filters to see all recorded threats'
                  : 'Processed emails will display threat indicators here'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px]">
                <thead>
                  <tr className="border-b border-neutral-100 bg-neutral-50">
                    {[
                      'Severity',
                      'Signal Finding',
                      'Attack Type',
                      'Extracted Indicator',
                      'Source Engine',
                      'Confidence',
                      'Observed Date',
                      '',
                    ].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-xs font-semibold text-neutral-400 uppercase tracking-wider"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-50">
                  {data?.items.map((signal) => (
                    <ThreatRow
                      key={signal.id}
                      signal={signal}
                      onViewAnalysis={() => navigate(`/analysis/${signal.analysis_id}`)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          {data && data.total > 20 && (
            <div className="flex items-center justify-between px-6 py-4 border-t border-neutral-100">
              <p className="text-sm text-neutral-500">
                Showing {(page - 1) * 20 + 1}–{Math.min(page * 20, data.total)} of{' '}
                {data.total.toLocaleString()}
              </p>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                  className="p-2 rounded-lg border border-neutral-200 text-neutral-600 hover:bg-neutral-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <span className="text-sm text-neutral-600 font-medium">
                  {page} / {totalPages}
                </span>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="p-2 rounded-lg border border-neutral-200 text-neutral-600 hover:bg-neutral-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  )
}
