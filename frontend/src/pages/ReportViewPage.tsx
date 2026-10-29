import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Printer,
  Download,
  ExternalLink,
  ArrowLeft,
  Shield,
  Brain,
  Cpu,
  Globe,
  Lock,
  AlertOctagon,
  Clock,
  UserCheck,
} from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import {
  Card,
  CardHeader,
  CardTitle,
  CardBody,
  Skeleton,
  Alert,
  Button,
} from '../shared/ui'
import { reportsApi } from '../shared/api/reports.api'
import type { AnalysisReport } from '../entities/report'

function riskColorClasses(level: string): { fg: string; bg: string; border: string } {
  switch (level.toLowerCase()) {
    case 'critical':
      return { fg: 'text-danger-700', bg: 'bg-danger-50', border: 'border-danger-200' }
    case 'high':
      return { fg: 'text-coral-700', bg: 'bg-coral-50', border: 'border-coral-200' }
    case 'medium':
      return { fg: 'text-warning-700', bg: 'bg-warning-50', border: 'border-warning-200' }
    case 'low':
      return { fg: 'text-success-700', bg: 'bg-success-50', border: 'border-success-200' }
    default:
      return { fg: 'text-neutral-700', bg: 'bg-neutral-50', border: 'border-neutral-200' }
  }
}

export function ReportViewPage() {
  const { id } = useParams<{ id: string }>()

  const { data: report, isLoading, isError, error } = useQuery<AnalysisReport>({
    queryKey: ['analysis-report', id],
    queryFn: () => reportsApi.getReportJson(id!),
    enabled: !!id,
    staleTime: 60_000,
  })

  if (isLoading) {
    return (
      <AppShell>
        <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">
          <Skeleton className="h-10 w-48 rounded-xl" />
          <Skeleton className="h-32 w-full rounded-2xl" />
          <Skeleton className="h-64 w-full rounded-2xl" />
        </div>
      </AppShell>
    )
  }

  if (isError || !report) {
    return (
      <AppShell>
        <div className="max-w-4xl mx-auto px-4 py-8">
          <Alert variant="error" title="Failed to Load Report">
            {error instanceof Error ? error.message : 'Unable to generate report.'}
          </Alert>
          <div className="mt-4">
            <Link to={id ? `/analysis/${id}` : '/history'}>
              <Button variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4 mr-1" /> Back to Analysis
              </Button>
            </Link>
          </div>
        </div>
      </AppShell>
    )
  }

  const riskClasses = riskColorClasses(report.risk_score.risk_level)

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Navigation & Action Bar */}
        <div className="print:hidden flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2 border-b border-neutral-200">
          <Link
            to={`/analysis/${id}`}
            className="flex items-center gap-1.5 text-sm font-medium text-neutral-600 hover:text-neutral-900 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" /> Back to Forensic Analysis
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => reportsApi.downloadReportJson(id!)}
              leftIcon={<Download className="h-3.5 w-3.5" />}
            >
              Export JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => reportsApi.openReportHtml(id!)}
              leftIcon={<ExternalLink className="h-3.5 w-3.5" />}
            >
              Open HTML
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => window.print()}
              leftIcon={<Printer className="h-3.5 w-3.5" />}
            >
              Print / Save PDF
            </Button>
          </div>
        </div>

        {/* Printable Report Canvas */}
        <div className="bg-white border border-neutral-200 rounded-2xl shadow-card p-6 sm:p-10 space-y-8 print:border-none print:shadow-none print:p-0">
          {/* Header Metadata */}
          <div className="flex flex-col sm:flex-row justify-between items-start gap-4 pb-6 border-b border-neutral-150">
            <div>
              <div className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-violet-600" />
                <h1 className="text-2xl font-bold text-neutral-900 tracking-tight">
                  Email Security Incident Report
                </h1>
              </div>
              <p className="text-xs text-neutral-500 mt-1 font-mono">
                Report ID: {report.report_id} &bull; Engine v{report.engine_version} (Scoring v{report.scoring_version})
              </p>
              {report.org_name && (
                <p className="text-xs font-semibold text-neutral-600 mt-0.5">
                  Tenant: {report.org_name}
                </p>
              )}
            </div>
            <div className="px-3 py-1 rounded-lg border border-danger-200 bg-danger-50 text-danger-700 text-xs font-bold uppercase tracking-wider">
              {report.confidentiality}
            </div>
          </div>

          {/* Verdict Banner */}
          <div className={`p-6 rounded-2xl border-2 ${riskClasses.bg} ${riskClasses.border} flex flex-col sm:flex-row items-start sm:items-center gap-6`}>
            <div className={`w-20 h-20 rounded-xl bg-white border-2 ${riskClasses.border} flex flex-col items-center justify-center shadow-xs flex-shrink-0`}>
              <span className={`text-3xl font-extrabold ${riskClasses.fg} tabular-nums`}>
                {report.risk_score.overall_risk_score}
              </span>
              <span className="text-2xs font-bold text-neutral-500 uppercase tracking-wider">
                Risk Score
              </span>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className={`text-xl font-bold uppercase ${riskClasses.fg}`}>
                  Verdict: {report.classification.verdict}
                </span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${riskClasses.bg} ${riskClasses.fg} border ${riskClasses.border}`}>
                  {report.classification.severity} Risk
                </span>
              </div>
              <p className="text-sm text-neutral-600 mt-1">
                Primary Threat Classification:{' '}
                <strong className="text-neutral-800 capitalize">
                  {report.classification.primary_attack_type.replace(/_/g, ' ')}
                </strong>{' '}
                &bull; Confidence:{' '}
                <strong className="text-neutral-800">
                  {Math.round(report.classification.confidence * 100)}%
                </strong>
              </p>
            </div>
          </div>

          {/* Email Metadata */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-teal-600" />
                <CardTitle>Email Metadata</CardTitle>
              </div>
            </CardHeader>
            <CardBody>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <div>
                  <dt className="text-xs font-semibold text-neutral-400 uppercase">From</dt>
                  <dd className="font-mono text-neutral-900 break-all">{report.email_metadata.from_address}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold text-neutral-400 uppercase">Subject</dt>
                  <dd className="font-medium text-neutral-900">{report.email_metadata.subject || '—'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold text-neutral-400 uppercase">To</dt>
                  <dd className="text-neutral-700 break-all">
                    {report.email_metadata.to_addresses.join(', ') || 'Undisclosed recipients'}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold text-neutral-400 uppercase">Received At</dt>
                  <dd className="text-neutral-700">
                    {new Date(report.email_metadata.received_at).toUTCString()}
                  </dd>
                </div>
                {report.email_metadata.reply_to && (
                  <div>
                    <dt className="text-xs font-semibold text-neutral-400 uppercase">Reply-To</dt>
                    <dd className="font-mono text-neutral-700 break-all">{report.email_metadata.reply_to}</dd>
                  </div>
                )}
                <div>
                  <dt className="text-xs font-semibold text-neutral-400 uppercase">Message-ID</dt>
                  <dd className="font-mono text-xs text-neutral-500 break-all">{report.email_metadata.message_id || '—'}</dd>
                </div>
                <div className="sm:col-span-2 pt-2 border-t border-neutral-100 flex flex-wrap items-center gap-3">
                  <span className="text-xs font-semibold text-neutral-400 uppercase">Authentication:</span>
                  <span className="px-2 py-0.5 rounded border border-neutral-200 bg-neutral-50 text-neutral-700 text-xs font-mono">
                    SPF: {report.email_metadata.spf_status || 'N/A'}
                  </span>
                  <span className="px-2 py-0.5 rounded border border-neutral-200 bg-neutral-50 text-neutral-700 text-xs font-mono">
                    DKIM: {report.email_metadata.dkim_status || 'N/A'}
                  </span>
                  <span className="px-2 py-0.5 rounded border border-neutral-200 bg-neutral-50 text-neutral-700 text-xs font-mono">
                    DMARC: {report.email_metadata.dmarc_status || 'N/A'}
                  </span>
                  <span className="text-xs text-neutral-500 ml-auto">
                    {report.email_metadata.attachment_count} attachment(s) &bull; {report.email_metadata.url_count} URL(s)
                  </span>
                </div>
              </dl>
            </CardBody>
          </Card>

          {/* Forensic Evidence Section */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertOctagon className="h-4 w-4 text-neutral-600" />
                <CardTitle>Forensic Evidence & Findings ({report.evidence.length})</CardTitle>
              </div>
            </CardHeader>
            <CardBody>
              {report.evidence.length === 0 ? (
                <p className="text-sm text-neutral-500 italic">No adverse security evidence recorded.</p>
              ) : (
                <div className="space-y-4">
                  {report.evidence.map((ev, i) => (
                    <div key={i} className="p-4 rounded-xl border border-neutral-200 bg-white shadow-xs space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${riskColorClasses(ev.severity).bg} ${riskColorClasses(ev.severity).fg} ${riskColorClasses(ev.severity).border}`}>
                          {ev.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-teal-50 border border-teal-200 text-teal-700 text-xs font-medium">
                          {ev.source}
                        </span>
                        <span className="text-xs text-neutral-500 capitalize">
                          {ev.attack_type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-neutral-400 ml-auto tabular-nums">
                          Confidence: {Math.round(ev.confidence * 100)}%
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-neutral-900">{ev.title}</h4>
                      <p className="text-xs text-neutral-600">{ev.description}</p>
                      {ev.indicator_value && (
                        <div className="text-xs font-mono bg-neutral-50 border border-neutral-100 p-1.5 rounded text-teal-800 break-all">
                          Indicator: {ev.indicator_value}
                        </div>
                      )}
                      <div className="p-2.5 rounded-lg bg-sky-50 border-l-4 border-sky-500 text-xs text-sky-800">
                        <strong className="font-semibold">Why it matters:</strong> {ev.why_it_matters}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>

          {/* Machine Learning Analysis */}
          {report.ml_analysis && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-violet-600" />
                  <CardTitle>Machine Learning Classification</CardTitle>
                </div>
              </CardHeader>
              <CardBody>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                  <div>
                    <p className="text-xs font-semibold text-neutral-400 uppercase">Model Output</p>
                    <p className="text-2xl font-bold text-neutral-900 capitalize mt-1">
                      {report.ml_analysis.classification}
                    </p>
                    <div className="mt-2 space-y-1 text-xs text-neutral-500">
                      <div>Model: <strong className="text-neutral-800">{report.ml_analysis.model_name}</strong></div>
                      <div>Version: <code className="text-neutral-800 font-mono">{report.ml_analysis.model_version}</code></div>
                      <div>Confidence: <strong className="text-neutral-800">{Math.round(report.ml_analysis.confidence * 100)}%</strong></div>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-neutral-400 uppercase mb-2">Class Probabilities</p>
                    <div className="space-y-2 text-xs">
                      <div>
                        <div className="flex justify-between mb-0.5">
                          <span>Phishing:</span>
                          <span className="font-bold">{(report.ml_analysis.phishing_probability * 100).toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 bg-neutral-100 rounded-full overflow-hidden">
                          <div className="h-full bg-danger-500 rounded-full" style={{ width: `${report.ml_analysis.phishing_probability * 100}%` }} />
                        </div>
                      </div>
                      <div>
                        <div className="flex justify-between mb-0.5">
                          <span>Malware:</span>
                          <span className="font-bold">{(report.ml_analysis.malware_probability * 100).toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 bg-neutral-100 rounded-full overflow-hidden">
                          <div className="h-full bg-coral-500 rounded-full" style={{ width: `${report.ml_analysis.malware_probability * 100}%` }} />
                        </div>
                      </div>
                      <div>
                        <div className="flex justify-between mb-0.5">
                          <span>Spam:</span>
                          <span className="font-bold">{(report.ml_analysis.spam_probability * 100).toFixed(1)}%</span>
                        </div>
                        <div className="h-1.5 bg-neutral-100 rounded-full overflow-hidden">
                          <div className="h-full bg-warning-500 rounded-full" style={{ width: `${report.ml_analysis.spam_probability * 100}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardBody>
            </Card>
          )}

          {/* Groq Semantic Narrative */}
          {report.groq_analysis && (
            <Card className="border-violet-100 bg-violet-50/20">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Brain className="h-4 w-4 text-violet-600" />
                  <CardTitle>Semantic & Intent Analysis</CardTitle>
                  <span className="px-2 py-0.5 rounded bg-violet-600 text-white text-2xs font-bold">
                    AI • {report.groq_analysis.model_name}
                  </span>
                </div>
              </CardHeader>
              <CardBody className="space-y-4">
                {report.groq_analysis.executive_summary && (
                  <div>
                    <h5 className="text-xs font-semibold text-neutral-400 uppercase">Executive Summary</h5>
                    <p className="text-sm text-neutral-900 mt-1 leading-relaxed">
                      {report.groq_analysis.executive_summary}
                    </p>
                  </div>
                )}
                <div>
                  <h5 className="text-xs font-semibold text-neutral-400 uppercase">Threat Narrative</h5>
                  <p className="text-xs text-neutral-700 mt-1 leading-relaxed whitespace-pre-wrap">
                    {report.groq_analysis.threat_narrative}
                  </p>
                </div>
                {report.groq_analysis.reasoning && (
                  <div>
                    <h5 className="text-xs font-semibold text-neutral-400 uppercase">Reasoning Steps</h5>
                    <p className="text-xs text-neutral-600 mt-1 italic leading-relaxed">
                      {report.groq_analysis.reasoning}
                    </p>
                  </div>
                )}
                <div className="p-3 rounded-xl bg-white border border-violet-200 inline-block">
                  <span className="text-xs font-semibold text-neutral-500">Recommended Action:</span>{' '}
                  <span className="text-sm font-bold text-violet-800 uppercase">
                    {report.groq_analysis.recommended_action}
                  </span>
                </div>
              </CardBody>
            </Card>
          )}

          {/* Threat Intelligence */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-teal-600" />
                <CardTitle>External Threat Intelligence Feeds</CardTitle>
              </div>
            </CardHeader>
            <CardBody>
              {report.threat_intelligence.length === 0 ? (
                <p className="text-sm text-neutral-500 italic">No external threat intelligence queries recorded.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-neutral-200 text-left text-neutral-400 uppercase">
                        <th className="py-2">Indicator</th>
                        <th className="py-2">Type</th>
                        <th className="py-2">Provider</th>
                        <th className="py-2">Verdict</th>
                        <th className="py-2">Score</th>
                        <th className="py-2">Tags</th>
                        <th className="py-2">Checked</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-100">
                      {report.threat_intelligence.map((ti, i) => (
                        <tr key={i} className="hover:bg-neutral-50">
                          <td className="py-2 font-mono break-all text-neutral-900">{ti.indicator_value}</td>
                          <td className="py-2 uppercase text-neutral-600">{ti.indicator_type}</td>
                          <td className="py-2 font-semibold text-neutral-800">{ti.provider}</td>
                          <td className="py-2">
                            <span className={`px-2 py-0.5 rounded text-2xs font-bold uppercase border ${riskColorClasses(ti.reputation).bg} ${riskColorClasses(ti.reputation).fg} ${riskColorClasses(ti.reputation).border}`}>
                              {ti.reputation}
                            </span>
                          </td>
                          <td className="py-2 tabular-nums">{ti.threat_score ?? '—'}</td>
                          <td className="py-2 text-neutral-500">{ti.tags.join(', ') || '—'}</td>
                          <td className="py-2 text-neutral-400">
                            {new Date(ti.last_checked_at).toLocaleDateString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Audit & Compliance Footer */}
          <div className="pt-6 border-t border-neutral-200 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 text-xs text-neutral-400">
            <div className="flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-neutral-400" />
              <span>Generated by: <strong className="text-neutral-600">{report.generated_by}</strong></span>
              <span>&bull;</span>
              <Clock className="h-3.5 w-3.5 text-neutral-400" />
              <span>{new Date(report.timestamps.report_generated_at).toUTCString()}</span>
            </div>
            <div className="font-mono text-2xs">
              Analysis ID: {report.analysis_id}
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
