import { useState, useId } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  SlidersHorizontal,
  Shield,
} from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import {
  Badge,
  RiskBadge,
  Card,
  CardBody,
  Skeleton,
  EmptyState,
  Alert,
  Button,
} from '../shared/ui'
import { analysisApi, type AnalysisHistoryParams } from '../shared/api/analysis.api'
import type { AnalysisHistoryItem } from '../entities/emailAnalysis'

// ── Helpers ───────────────────────────────────────────────────────────────────

function riskScoreColor(score: number): string {
  if (score >= 80) return 'text-danger-600'
  if (score >= 60) return 'text-coral-600'
  if (score >= 40) return 'text-warning-600'
  return 'text-success-600'
}

function riskScoreBar(score: number): string {
  if (score >= 80) return 'bg-danger-500'
  if (score >= 60) return 'bg-coral-500'
  if (score >= 40) return 'bg-warning-500'
  return 'bg-success-500'
}

function classificationBadge(verdict: string) {
  const v = verdict.toLowerCase()
  if (v === 'malicious') return <Badge variant="danger">Malicious</Badge>
  if (v === 'suspicious') return <Badge variant="warning">Suspicious</Badge>
  if (v === 'clean') return <Badge variant="success">Clean</Badge>
  if (v === 'spam') return <Badge variant="neutral">Spam</Badge>
  return <Badge variant="neutral">{verdict}</Badge>
}

function statusBadge(status: string) {
  const s = status.toLowerCase()
  if (s === 'completed') return <Badge variant="success">Completed</Badge>
  if (s === 'processing') return <Badge variant="info">Processing</Badge>
  if (s === 'queued') return <Badge variant="neutral">Queued</Badge>
  return <Badge variant="danger">Failed</Badge>
}

// ── Component ─────────────────────────────────────────────────────────────────

export function AnalysisHistoryPage() {
  const navigate = useNavigate()

  // State: Pagination
  const [page, setPage] = useState<number>(1)
  const [pageSize, setPageSize] = useState<number>(20)

  // State: Sorting
  const [sortBy, setSortBy] = useState<string>('created_at')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  // State: Filters
  const [search, setSearch] = useState<string>('')
  const [senderFilter, setSenderFilter] = useState<string>('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [startDate, setStartDate] = useState<string>('')
  const [endDate, setEndDate] = useState<string>('')
  const [minRisk, setMinRisk] = useState<string>('')
  const [maxRisk, setMaxRisk] = useState<string>('')
  const [isFilterDrawerOpen, setIsFilterDrawerOpen] = useState<boolean>(false)

  // Date range presets helper
  const setDatePreset = (preset: 'today' | '7d' | '30d' | 'all') => {
    if (preset === 'all') {
      setStartDate('')
      setEndDate('')
      return
    }
    const now = new Date()
    setEndDate(now.toISOString().split('T')[0])
    if (preset === 'today') {
      setStartDate(now.toISOString().split('T')[0])
    } else if (preset === '7d') {
      const past = new Date()
      past.setDate(now.getDate() - 7)
      setStartDate(past.toISOString().split('T')[0])
    } else if (preset === '30d') {
      const past = new Date()
      past.setDate(now.getDate() - 30)
      setStartDate(past.toISOString().split('T')[0])
    }
    setPage(1)
  }

  // Clear all filters
  const resetFilters = () => {
    setSearch('')
    setSenderFilter('')
    setSeverityFilter('all')
    setAttackTypeFilter('all')
    setStatusFilter('all')
    setStartDate('')
    setEndDate('')
    setMinRisk('')
    setMaxRisk('')
    setPage(1)
  }

  // Active filter count
  const activeFilterCount = [
    search,
    senderFilter,
    severityFilter !== 'all',
    attackTypeFilter !== 'all',
    statusFilter !== 'all',
    startDate,
    endDate,
    minRisk,
    maxRisk,
  ].filter(Boolean).length

  // Build query params
  const queryParams: AnalysisHistoryParams = {
    page,
    page_size: pageSize,
    sort_by: sortBy,
    sort_order: sortOrder,
    search: search.trim() || undefined,
    sender: senderFilter.trim() || undefined,
    severity: severityFilter !== 'all' ? severityFilter : undefined,
    attack_type: attackTypeFilter !== 'all' ? attackTypeFilter : undefined,
    status: statusFilter !== 'all' ? statusFilter : undefined,
    start_date: startDate ? new Date(startDate).toISOString() : undefined,
    end_date: endDate ? new Date(endDate + 'T23:59:59Z').toISOString() : undefined,
    min_risk: minRisk ? parseInt(minRisk, 10) : undefined,
    max_risk: maxRisk ? parseInt(maxRisk, 10) : undefined,
  }

  // TanStack Query
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['analysis-history', queryParams],
    queryFn: () => analysisApi.getHistory(queryParams),
    placeholderData: (prev) => prev,
  })

  // Handle Sort Toggle
  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortOrder('desc')
    }
    setPage(1)
  }

  // Render sort indicator
  const renderSortIndicator = (field: string) => {
    if (sortBy !== field) {
      return <ArrowUpDown className="h-3 w-3 text-neutral-400 opacity-0 group-hover:opacity-100 transition-opacity" />
    }
    return sortOrder === 'asc' ? (
      <ArrowUp className="h-3 w-3 text-violet-600" />
    ) : (
      <ArrowDown className="h-3 w-3 text-violet-600" />
    )
  }

  const items = data?.items ?? []
  const totalCount = data?.total_count ?? 0
  const totalPages = data?.total_pages ?? 1

  const fromCount = totalCount === 0 ? 0 : (page - 1) * pageSize + 1
  const toCount = Math.min(page * pageSize, totalCount)

  const startDateId = useId()
  const endDateId = useId()

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        {/* Header Strip */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <h1 className="text-xl font-bold text-neutral-900 tracking-tight">Analysis History</h1>
            <p className="text-xs text-neutral-500 mt-0.5">
              Authoritative forensic audit log of all analyzed email payloads
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-neutral-500 bg-neutral-100 px-2.5 py-1 rounded-lg">
              {totalCount.toLocaleString()} Total Records
            </span>
          </div>
        </div>

        {/* Filter Toolbar Card */}
        <Card padding="none">
          <CardBody className="p-4 space-y-3">
            {/* Primary Search Bar + Quick Actions */}
            <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
              {/* Search box */}
              <div className="relative flex-1">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" />
                <input
                  type="text"
                  placeholder="Search by sender, domain, or subject..."
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                  className="w-full pl-10 pr-4 py-2 bg-neutral-50 border border-neutral-200 rounded-xl text-xs text-neutral-800 placeholder-neutral-400 focus:outline-none focus:ring-2 focus:ring-violet-500 focus:bg-white transition-all"
                />
              </div>

              {/* Date Presets */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                <button
                  type="button"
                  onClick={() => setDatePreset('all')}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors shrink-0 ${
                    !startDate && !endDate
                      ? 'bg-violet-100 text-violet-700'
                      : 'bg-neutral-100 text-neutral-600 hover:bg-neutral-200'
                  }`}
                >
                  All Time
                </button>
                <button
                  type="button"
                  onClick={() => setDatePreset('today')}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-neutral-100 text-neutral-600 hover:bg-neutral-200 transition-colors shrink-0"
                >
                  Today
                </button>
                <button
                  type="button"
                  onClick={() => setDatePreset('7d')}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-neutral-100 text-neutral-600 hover:bg-neutral-200 transition-colors shrink-0"
                >
                  7 Days
                </button>
                <button
                  type="button"
                  onClick={() => setDatePreset('30d')}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-neutral-100 text-neutral-600 hover:bg-neutral-200 transition-colors shrink-0"
                >
                  30 Days
                </button>

                {/* Toggle Filter Drawer */}
                <Button
                  variant={isFilterDrawerOpen || activeFilterCount > 0 ? 'secondary' : 'ghost'}
                  size="sm"
                  onClick={() => setIsFilterDrawerOpen(!isFilterDrawerOpen)}
                  className="shrink-0 gap-1.5 text-xs"
                >
                  <SlidersHorizontal className="h-3.5 w-3.5" />
                  Filters
                  {activeFilterCount > 0 && (
                    <span className="h-4 w-4 rounded-full bg-violet-600 text-white text-2xs flex items-center justify-center font-bold">
                      {activeFilterCount}
                    </span>
                  )}
                </Button>

                {activeFilterCount > 0 && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="p-1.5 rounded-lg text-neutral-400 hover:text-neutral-700 hover:bg-neutral-100 transition-colors shrink-0"
                    title="Reset all filters"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Expandable Advanced Filters Tray */}
            {isFilterDrawerOpen && (
              <div className="pt-3 border-t border-neutral-150 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs animate-fade-in">
                {/* Severity Filter */}
                <div>
                  <label htmlFor="filter-severity" className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Severity
                  </label>
                  <select
                    id="filter-severity"
                    value={severityFilter}
                    onChange={(e) => {
                      setSeverityFilter(e.target.value)
                      setPage(1)
                    }}
                    className="w-full px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="safe">Safe</option>
                  </select>
                </div>

                {/* Attack Type Filter */}
                <div>
                  <label htmlFor="filter-attack-type" className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Attack Vector
                  </label>
                  <select
                    id="filter-attack-type"
                    value={attackTypeFilter}
                    onChange={(e) => {
                      setAttackTypeFilter(e.target.value)
                      setPage(1)
                    }}
                    className="w-full px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                  >
                    <option value="all">All Attack Types</option>
                    <option value="phishing">Phishing</option>
                    <option value="credential_harvesting">Credential Harvesting</option>
                    <option value="bec">Business Email Compromise (BEC)</option>
                    <option value="malware">Malware / Dropper</option>
                    <option value="spoofing">Domain Spoofing</option>
                    <option value="extortion">Extortion / Blackmail</option>
                    <option value="social_engineering">Social Engineering</option>
                  </select>
                </div>

                {/* Sender Email / Domain */}
                <div>
                  <label htmlFor="filter-sender" className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Sender Filter
                  </label>
                  <input
                    id="filter-sender"
                    type="text"
                    placeholder="e.g. attacker.com"
                    value={senderFilter}
                    onChange={(e) => {
                      setSenderFilter(e.target.value)
                      setPage(1)
                    }}
                    className="w-full px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                  />
                </div>

                {/* Status Filter */}
                <div>
                  <label htmlFor="filter-status" className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Status
                  </label>
                  <select
                    id="filter-status"
                    value={statusFilter}
                    onChange={(e) => {
                      setStatusFilter(e.target.value)
                      setPage(1)
                    }}
                    className="w-full px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                  >
                    <option value="all">All Statuses</option>
                    <option value="completed">Completed</option>
                    <option value="processing">Processing</option>
                    <option value="queued">Queued</option>
                    <option value="failed">Failed</option>
                  </select>
                </div>

                {/* Custom Date Range */}
                <div className="sm:col-span-2">
                  <span className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Custom Date Range
                  </span>
                  <div className="flex items-center gap-2">
                    <input
                      id={startDateId}
                      aria-label="Start date"
                      type="date"
                      value={startDate}
                      onChange={(e) => {
                        setStartDate(e.target.value)
                        setPage(1)
                      }}
                      className="flex-1 px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                    />
                    <span className="text-neutral-400">to</span>
                    <input
                      id={endDateId}
                      aria-label="End date"
                      type="date"
                      value={endDate}
                      onChange={(e) => {
                        setEndDate(e.target.value)
                        setPage(1)
                      }}
                      className="flex-1 px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                    />
                  </div>
                </div>

                {/* Risk Range */}
                <div className="sm:col-span-2">
                  <span className="block text-2xs font-bold text-neutral-400 uppercase tracking-wider mb-1">
                    Risk Score Range (0 - 100)
                  </span>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min="0"
                      max="100"
                      placeholder="Min (0)"
                      value={minRisk}
                      onChange={(e) => {
                        setMinRisk(e.target.value)
                        setPage(1)
                      }}
                      className="w-1/2 px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                    />
                    <span className="text-neutral-400">-</span>
                    <input
                      type="number"
                      min="0"
                      max="100"
                      placeholder="Max (100)"
                      value={maxRisk}
                      onChange={(e) => {
                        setMaxRisk(e.target.value)
                        setPage(1)
                      }}
                      className="w-1/2 px-3 py-1.5 bg-neutral-50 border border-neutral-200 rounded-lg text-xs text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                    />
                  </div>
                </div>
              </div>
            )}
          </CardBody>
        </Card>

        {/* Error Alert */}
        {isError && (
          <Alert variant="error" title="Failed to load analysis history">
            {error instanceof Error ? error.message : 'An error occurred while querying the server.'}
          </Alert>
        )}

        {/* High-Density Results Table */}
        <Card padding="none">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[850px] border-collapse text-left">
              <thead>
                <tr className="border-b border-neutral-150 bg-neutral-50/70 text-2xs font-bold text-neutral-500 uppercase tracking-wider select-none">
                  {/* Timestamp */}
                  <th
                    scope="col"
                    onClick={() => handleSort('created_at')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Timestamp</span>
                      {renderSortIndicator('created_at')}
                    </div>
                  </th>

                  {/* Sender */}
                  <th
                    scope="col"
                    onClick={() => handleSort('sender')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Sender</span>
                      {renderSortIndicator('sender')}
                    </div>
                  </th>

                  {/* Subject */}
                  <th
                    scope="col"
                    onClick={() => handleSort('subject')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Subject</span>
                      {renderSortIndicator('subject')}
                    </div>
                  </th>

                  {/* Classification */}
                  <th
                    scope="col"
                    onClick={() => handleSort('classification')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Classification</span>
                      {renderSortIndicator('classification')}
                    </div>
                  </th>

                  {/* Severity */}
                  <th
                    scope="col"
                    onClick={() => handleSort('severity')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Severity</span>
                      {renderSortIndicator('severity')}
                    </div>
                  </th>

                  {/* Risk */}
                  <th
                    scope="col"
                    onClick={() => handleSort('risk_score')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Risk</span>
                      {renderSortIndicator('risk_score')}
                    </div>
                  </th>

                  {/* Status */}
                  <th
                    scope="col"
                    onClick={() => handleSort('status')}
                    className="px-5 py-3.5 cursor-pointer hover:bg-neutral-100 transition-colors group"
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Status</span>
                      {renderSortIndicator('status')}
                    </div>
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-neutral-100 text-xs">
                {/* Loading skeleton rows */}
                {isLoading && (
                  <>
                    {[1, 2, 3, 4, 5].map((i) => (
                      <tr key={i} className="animate-pulse">
                        <td className="px-5 py-3.5"><Skeleton className="h-4 w-28" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-4 w-40" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-4 w-48" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-5 w-20 rounded-md" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-5 w-16 rounded-md" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-4 w-16" /></td>
                        <td className="px-5 py-3.5"><Skeleton className="h-5 w-20 rounded-md" /></td>
                      </tr>
                    ))}
                  </>
                )}

                {/* Empty State */}
                {!isLoading && items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-5 py-12 text-center">
                      <EmptyState
                        icon={<Shield className="h-10 w-10 text-neutral-300" />}
                        title="No matching analysis records found"
                        description={
                          activeFilterCount > 0
                            ? 'Try clearing your search query or relaxing filter constraints.'
                            : 'No emails have been submitted for threat analysis yet.'
                        }
                        action={
                          activeFilterCount > 0 ? (
                            <Button variant="secondary" size="sm" onClick={resetFilters}>
                              Reset Filters
                            </Button>
                          ) : undefined
                        }
                      />
                    </td>
                  </tr>
                )}

                {/* Data Rows */}
                {!isLoading &&
                  items.map((item: AnalysisHistoryItem) => {
                    const safeLevel = (
                      ['critical', 'high', 'medium', 'low', 'safe'] as const
                    ).includes(item.severity.toLowerCase() as any)
                      ? (item.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'safe')
                      : 'low'

                    return (
                      <tr
                        key={item.analysis_id}
                        tabIndex={0}
                        onClick={() => navigate(`/analysis/${item.analysis_id}`)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') navigate(`/analysis/${item.analysis_id}`)
                        }}
                        className="cursor-pointer hover:bg-violet-50/40 transition-colors focus:outline-none focus:bg-violet-50/60"
                      >
                        {/* 1. Timestamp */}
                        <td className="px-5 py-3.5 whitespace-nowrap text-neutral-500 font-medium">
                          <span title={item.timestamp}>
                            {new Date(item.timestamp).toLocaleDateString([], {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric',
                            })}{' '}
                            <span className="text-2xs text-neutral-400">
                              {new Date(item.timestamp).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit',
                              })}
                            </span>
                          </span>
                        </td>

                        {/* 2. Sender */}
                        <td className="px-5 py-3.5 max-w-[220px]">
                          <div className="flex flex-col">
                            <span className="font-semibold text-neutral-900 truncate" title={item.sender}>
                              {item.sender}
                            </span>
                            <span className="text-2xs text-teal-700 font-mono truncate" title={item.sender_domain}>
                              @{item.sender_domain}
                            </span>
                          </div>
                        </td>

                        {/* 3. Subject */}
                        <td className="px-5 py-3.5 max-w-[260px]">
                          <p className="text-neutral-700 font-medium truncate" title={item.subject}>
                            {item.subject}
                          </p>
                          {item.attack_type && item.attack_type !== 'none' && (
                            <span className="inline-block text-2xs text-neutral-400 uppercase tracking-wide mt-0.5">
                              {item.attack_type.replace(/_/g, ' ')}
                            </span>
                          )}
                        </td>

                        {/* 4. Classification */}
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          {classificationBadge(item.classification)}
                        </td>

                        {/* 5. Severity */}
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <RiskBadge level={safeLevel} />
                        </td>

                        {/* 6. Risk */}
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-sm font-bold tabular-nums ${riskScoreColor(
                                item.risk_score
                              )}`}
                            >
                              {item.risk_score}
                            </span>
                            <div className="w-12 h-1.5 bg-neutral-100 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${riskScoreBar(item.risk_score)}`}
                                style={{ width: `${item.risk_score}%` }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* 7. Status */}
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          {statusBadge(item.status)}
                        </td>
                      </tr>
                    )
                  })}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="px-5 py-3.5 border-t border-neutral-150 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs bg-neutral-50/50">
            {/* Range text */}
            <p className="text-neutral-500 font-medium">
              Showing <span className="text-neutral-800 font-bold">{fromCount}</span> to{' '}
              <span className="text-neutral-800 font-bold">{toCount}</span> of{' '}
              <span className="text-neutral-800 font-bold">{totalCount}</span> results
            </p>

            {/* Pagination Controls */}
            <div className="flex items-center gap-3">
              {/* Page size dropdown */}
              <div className="flex items-center gap-1.5 text-neutral-500">
                <span>Per page:</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(parseInt(e.target.value, 10))
                    setPage(1)
                  }}
                  className="px-2 py-1 bg-white border border-neutral-200 rounded-lg text-xs font-semibold text-neutral-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>

              {/* Prev / Next buttons */}
              <div className="flex items-center gap-1">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1 || isLoading}
                  className="px-2 py-1"
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>

                <span className="px-3 py-1 font-semibold text-neutral-700 bg-white border border-neutral-200 rounded-lg">
                  {page} / {totalPages}
                </span>

                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages || isLoading}
                  className="px-2 py-1"
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </AppShell>
  )
}
