import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  BarChart3,
  Download,
  FileSpreadsheet,
  FileText,
  Printer,
  ExternalLink,
  CheckCircle2,
  FileCheck,
} from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import {
  RiskBadge,
  Card,
  CardHeader,
  CardTitle,
  CardBody,
  Button,
  Skeleton,
  EmptyState,
} from '../shared/ui'
import { analysisApi } from '../shared/api/analysis.api'
import { reportsApi } from '../shared/api/reports.api'
import { analyticsApi } from '../shared/api/analytics.api'

export function ReportsPage() {
  const [downloadingId, setDownloadingId] = useState<string | null>(null)

  // Fetch recent completed analyses to populate compliance dossiers
  const { data: historyData, isLoading } = useQuery({
    queryKey: ['reports-history-list'],
    queryFn: () => analysisApi.getHistory({ page: 1, page_size: 12 }),
    staleTime: 30_000,
  })

  const handleDownloadJson = async (analysisId: string) => {
    try {
      setDownloadingId(analysisId)
      await reportsApi.downloadReportJson(analysisId)
    } finally {
      setDownloadingId(null)
    }
  }

  const csvExportUrl = analyticsApi.getExportUrl({ preset: '30d' })

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">
                Security & Compliance Reports
              </h1>
              <span className="inline-flex items-center gap-1 rounded-full bg-violet-50 px-2.5 py-0.5 text-2xs font-semibold text-violet-700 border border-violet-200/80">
                SOC2 / ISO 27001 Ready
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Generate executive summaries, forensic investigation packages, and compliance audit exports
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <a href={csvExportUrl} download="security_analytics_30d.csv">
              <Button
                variant="outline"
                size="sm"
                leftIcon={<FileSpreadsheet className="h-4 w-4 text-emerald-600" />}
              >
                Export CSV Telemetry (30D)
              </Button>
            </a>
          </div>
        </div>

        {/* 3 Executive Compliance Anchors */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="p-5 border-slate-200/90 shadow-2xs">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Audit Trail Integrity
                </p>
                <p className="text-2xl font-bold text-slate-900 mt-1">100% Immutable</p>
                <p className="text-xs text-slate-500 mt-1">
                  PostgreSQL foreign key relations with cryptographic sha256 checksums
                </p>
              </div>
              <span className="p-2.5 bg-emerald-50 text-emerald-600 rounded-xl">
                <FileCheck className="h-5 w-5" />
              </span>
            </div>
          </Card>

          <Card className="p-5 border-slate-200/90 shadow-2xs">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Forensic Retention
                </p>
                <p className="text-2xl font-bold text-slate-900 mt-1">Full Headers & RFC</p>
                <p className="text-xs text-slate-500 mt-1">
                  Full raw authentication passes (SPF, DKIM, DMARC) preserved for discovery
                </p>
              </div>
              <span className="p-2.5 bg-sky-50 text-sky-600 rounded-xl">
                <CheckCircle2 className="h-5 w-5" />
              </span>
            </div>
          </Card>

          <Card className="p-5 border-slate-200/90 shadow-2xs">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Report Formats
                </p>
                <p className="text-2xl font-bold text-slate-900 mt-1">PDF / HTML / JSON</p>
                <p className="text-xs text-slate-500 mt-1">
                  Interactive browser dossiers, printable audit reports, and raw SIEM feeds
                </p>
              </div>
              <span className="p-2.5 bg-violet-50 text-violet-600 rounded-xl">
                <Printer className="h-5 w-5" />
              </span>
            </div>
          </Card>
        </div>

        {/* Incident Investigation Reports Dossiers */}
        <Card className="border-slate-200/90 shadow-2xs overflow-hidden">
          <CardHeader>
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-violet-600" />
                <CardTitle>Recent Incident Reports & Forensic Dossiers</CardTitle>
              </div>
              <span className="text-xs text-slate-400">
                {historyData?.total_count ?? 0} total records
              </span>
            </div>
          </CardHeader>
          <CardBody className="p-0">
            {isLoading ? (
              <div className="p-6 space-y-3">
                {[1, 2, 3, 4].map((i) => (
                  <Skeleton key={i} className="h-14 w-full rounded-xl" />
                ))}
              </div>
            ) : !historyData?.items || historyData.items.length === 0 ? (
              <div className="p-12">
                <EmptyState
                  icon={<BarChart3 className="h-8 w-8 text-slate-300" />}
                  title="No Incident Reports Available"
                  description="Run an email analysis to generate compliance dossiers."
                  action={
                    <Link to="/analyze">
                      <Button variant="primary" size="sm">
                        Analyze an Email
                      </Button>
                    </Link>
                  }
                />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200/80 bg-slate-50/70 text-[11px] font-bold uppercase tracking-wider text-slate-500">
                    <tr>
                      <th className="px-6 py-3">Subject / Incident</th>
                      <th className="px-6 py-3">Risk Assessment</th>
                      <th className="px-6 py-3">Sender Domain</th>
                      <th className="px-6 py-3">Analyzed At</th>
                      <th className="px-6 py-3 text-right">Export Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {historyData.items.map((item) => {
                      const safeLevel = (
                        ['critical', 'high', 'medium', 'low', 'safe'] as const
                      ).includes(
                        item.severity?.toLowerCase() as
                          | 'critical'
                          | 'high'
                          | 'medium'
                          | 'low'
                          | 'safe',
                      )
                        ? (item.severity.toLowerCase() as
                            | 'critical'
                            | 'high'
                            | 'medium'
                            | 'low'
                            | 'safe')
                        : item.risk_score >= 80
                          ? 'critical'
                          : item.risk_score >= 60
                            ? 'high'
                            : item.risk_score >= 40
                              ? 'medium'
                              : 'safe'

                      return (
                        <tr
                          key={item.analysis_id}
                          className="hover:bg-slate-50/80 transition-colors group"
                        >
                          <td className="px-6 py-3.5 max-w-[280px]">
                            <p className="font-semibold text-slate-800 truncate">
                              {item.subject || '(No Subject)'}
                            </p>
                            <p className="text-[10px] text-slate-400 font-mono truncate mt-0.5">
                              ID: {item.analysis_id}
                            </p>
                          </td>

                          <td className="px-6 py-3.5">
                            <div className="flex items-center gap-2">
                              <RiskBadge level={safeLevel} />
                              <span className="font-bold tabular-nums text-slate-700">
                                {item.risk_score}/100
                              </span>
                            </div>
                          </td>

                          <td className="px-6 py-3.5 text-slate-600 font-medium">
                            {item.sender_domain}
                          </td>

                          <td className="px-6 py-3.5 text-slate-400">
                            {new Date(item.timestamp).toLocaleString()}
                          </td>

                          <td className="px-6 py-3.5 text-right">
                            <div className="inline-flex items-center gap-1.5 opacity-80 group-hover:opacity-100 transition-opacity">
                              {/* Open printable HTML incident report */}
                              <button
                                type="button"
                                onClick={() => reportsApi.openReportHtml(item.analysis_id)}
                                title="Open Print-Ready Incident Report"
                                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-slate-600 hover:border-violet-300 hover:text-violet-700 transition-colors"
                              >
                                <Printer className="h-3 w-3" />
                                <span>Print Report</span>
                              </button>

                              {/* Download structured JSON */}
                              <button
                                type="button"
                                disabled={downloadingId === item.analysis_id}
                                onClick={() => handleDownloadJson(item.analysis_id)}
                                title="Download JSON Dossier"
                                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-slate-600 hover:border-violet-300 hover:text-violet-700 transition-colors"
                              >
                                <Download className="h-3 w-3" />
                                <span>JSON</span>
                              </button>

                              {/* View interactive detail page */}
                              <Link
                                to={`/analysis/${item.analysis_id}`}
                                title="Open Interactive Forensic Dossier"
                                className="inline-flex items-center gap-1 rounded-lg bg-violet-50 border border-violet-200/80 px-2.5 py-1 text-violet-700 hover:bg-violet-100 transition-colors font-medium"
                              >
                                <ExternalLink className="h-3 w-3" />
                                <span>Dossier</span>
                              </Link>
                            </div>
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
      </div>
    </AppShell>
  )
}
