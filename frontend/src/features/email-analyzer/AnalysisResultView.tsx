import { type FC, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowLeft,
  Copy,
  Download,
  ExternalLink,
  FileSpreadsheet,
  FileText,
  Globe,
  Paperclip,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import type { EmailAnalysisResult } from '../../entities/emailAnalysis'
import { FieldRow, RiskMeter, SectionCard, StatusBadge } from '../../shared/ui/AnalyzerPrimitives'

interface AnalysisResultViewProps {
  result: EmailAnalysisResult
  onReset: () => void
}

export const AnalysisResultView: FC<AnalysisResultViewProps> = ({ result, onReset }) => {
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState<'overview' | 'urls' | 'headers' | 'attachments' | 'body'>('overview')

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threat-analysis-${result.email_id.substring(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const isMalicious = result.verdict === 'malicious'
  const isSuspicious = result.verdict === 'suspicious'

  return (
    <div className="space-y-6">
      {/* Top Banner & Verdict Card */}
      <div
        className={`rounded-2xl border p-6 shadow-sm transition-all ${
          isMalicious
            ? 'border-red-200 bg-red-50/40'
            : isSuspicious
              ? 'border-amber-200 bg-amber-50/40'
              : 'border-green-200 bg-green-50/40'
        }`}
      >
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-4">
            <span
              className={`p-3.5 rounded-2xl shadow-sm shrink-0 ${
                isMalicious
                  ? 'bg-red-600 text-white'
                  : isSuspicious
                    ? 'bg-amber-500 text-white'
                    : 'bg-green-600 text-white'
              }`}
            >
              {isMalicious ? (
                <ShieldAlert className="h-8 w-8" />
              ) : isSuspicious ? (
                <AlertTriangle className="h-8 w-8" />
              ) : (
                <ShieldCheck className="h-8 w-8" />
              )}
            </span>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2.5">
                <h2 className="text-xl font-bold text-gray-900 capitalize">
                  {result.verdict} Email Detected
                </h2>
                <StatusBadge
                  variant={isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'clean'}
                  label={result.verdict}
                />
              </div>
              <p className="text-sm text-gray-600 max-w-2xl">
                {isMalicious
                  ? 'High-confidence indicators of malicious phishing or threat payload detected. Block sender and quarantine message.'
                  : isSuspicious
                    ? 'Anomalies or authentication discrepancies observed. Exercise caution before opening links or attachments.'
                    : 'No suspicious indicators or authentication failures found. Sender and routing appear legitimate.'}
              </p>
              <p className="text-xs text-gray-400 font-mono pt-1">
                Analysis ID: {result.analysis_id} • Target Email ID: {result.email_id}
              </p>
            </div>
          </div>

          {/* Risk Score Widget */}
          <div className="w-full sm:w-64 rounded-xl bg-white p-4 shadow-sm border border-gray-100 shrink-0">
            <RiskMeter score={result.initial_risk_score} level={result.initial_risk_level} />
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-gray-200/60">
          <button
            type="button"
            onClick={onReset}
            className="btn-secondary !py-2 !px-4 text-xs font-semibold"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Analyze Another Email
          </button>

          <div className="flex items-center gap-2">
            <Link
              to={`/analysis/${result.analysis_id}`}
              className="btn-primary !py-2 !px-3.5 text-xs shadow-none inline-flex items-center gap-1.5"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              <span>Full Investigation Dossier</span>
            </Link>
            <button
              type="button"
              onClick={copyJson}
              className="btn-secondary !py-2 !px-3 text-xs"
            >
              <Copy className="h-3.5 w-3.5" /> {copied ? 'Copied!' : 'Copy Telemetry'}
            </button>
            <button
              type="button"
              onClick={downloadJson}
              className="btn-secondary !py-2 !px-3 text-xs"
            >
              <Download className="h-3.5 w-3.5" /> Export JSON
            </button>
          </div>
        </div>
      </div>

      {/* Threat Signals Alert Box (if any) */}
      {result.threat_signals.length > 0 && (
        <div className="rounded-xl border border-red-200 bg-red-50/70 p-5 shadow-sm space-y-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-600" />
            <h3 className="text-sm font-bold text-red-900">
              {result.threat_signals.length} Security Signals Triggered
            </h3>
          </div>
          <ul className="space-y-1.5 pl-7 list-disc text-xs text-red-800">
            {result.threat_signals.map((sig, i) => (
              <li key={i} className="font-medium leading-relaxed">
                {sig}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8" aria-label="Tabs">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={activeTab === 'overview' ? 'tab-active' : 'tab-inactive'}
          >
            Overview & Auth
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('urls')}
            className={activeTab === 'urls' ? 'tab-active' : 'tab-inactive'}
          >
            Extracted URLs ({result.urls.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('headers')}
            className={activeTab === 'headers' ? 'tab-active' : 'tab-inactive'}
          >
            RFC Headers
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('attachments')}
            className={activeTab === 'attachments' ? 'tab-active' : 'tab-inactive'}
          >
            Attachments ({result.attachments.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('body')}
            className={activeTab === 'body' ? 'tab-active' : 'tab-inactive'}
          >
            Message Body
          </button>
        </nav>
      </div>

      {/* Tab 1: Overview & Authentication */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Metadata Card */}
          <SectionCard title="Email Metadata" icon={<FileText className="h-4 w-4" />}>
            <dl className="space-y-3">
              <FieldRow label="From" value={result.from_address} />
              <FieldRow label="Sender Domain" value={result.from_domain} mono />
              <FieldRow label="To" value={result.to_addresses.join(', ')} />
              {result.cc_addresses.length > 0 && (
                <FieldRow label="CC" value={result.cc_addresses.join(', ')} />
              )}
              {result.reply_to && <FieldRow label="Reply-To" value={result.reply_to} />}
              <FieldRow label="Subject" value={result.subject || '(No subject)'} />
              <FieldRow
                label="Timestamp"
                value={new Date(result.received_at).toLocaleString()}
              />
              <FieldRow label="Message-ID" value={result.message_id} mono />
            </dl>
          </SectionCard>

          {/* Authentication Results Card */}
          <SectionCard title="Authentication Verdicts" icon={<Shield className="h-4 w-4" />}>
            <div className="space-y-4">
              {/* SPF */}
              <div className="rounded-lg border border-gray-100 bg-gray-50/60 p-3.5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-800">SPF Verification</span>
                  <StatusBadge
                    variant={
                      result.headers.spf_status === 'pass'
                        ? 'pass'
                        : result.headers.spf_status === 'fail'
                          ? 'fail'
                          : 'none'
                    }
                    label={result.headers.spf_status}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {result.headers.spf_details ||
                    (result.headers.spf_status === 'pass'
                      ? 'Sender IP matches SPF policy'
                      : 'No SPF record or match verification')}
                </p>
              </div>

              {/* DKIM */}
              <div className="rounded-lg border border-gray-100 bg-gray-50/60 p-3.5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-800">DKIM Cryptographic Signature</span>
                  <StatusBadge
                    variant={
                      result.headers.dkim_status === 'pass'
                        ? 'pass'
                        : result.headers.dkim_status === 'fail'
                          ? 'fail'
                          : 'none'
                    }
                    label={result.headers.dkim_status}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {result.headers.dkim_details ||
                    (result.headers.dkim_status === 'pass'
                      ? 'Cryptographic signature is valid'
                      : 'No signature found or verification softfailed')}
                </p>
              </div>

              {/* DMARC */}
              <div className="rounded-lg border border-gray-100 bg-gray-50/60 p-3.5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-800">DMARC Policy Alignment</span>
                  <StatusBadge
                    variant={
                      result.headers.dmarc_status === 'pass'
                        ? 'pass'
                        : result.headers.dmarc_status === 'fail'
                          ? 'fail'
                          : 'none'
                    }
                    label={result.headers.dmarc_status}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {result.headers.dmarc_details ||
                    (result.headers.dmarc_status === 'pass'
                      ? 'Domain alignment and policy enforcement passed'
                      : 'Unaligned or policy not specified')}
                </p>
              </div>
            </div>
          </SectionCard>
        </div>
      )}

      {/* Tab 2: Extracted URLs */}
      {activeTab === 'urls' && (
        <SectionCard
          title={`Detected URLs (${result.urls.length})`}
          icon={<Globe className="h-4 w-4" />}
          badge={<span className="text-xs text-gray-400">Defanged for security</span>}
        >
          {result.urls.length === 0 ? (
            <p className="text-sm text-gray-500">No URLs were found in this email message.</p>
          ) : (
            <div className="divide-y divide-gray-100 overflow-hidden rounded-lg border border-gray-200 bg-white">
              {result.urls.map((u, i) => (
                <div
                  key={i}
                  className="flex flex-col gap-2 p-3.5 sm:flex-row sm:items-center sm:justify-between hover:bg-violet-50/20 transition-colors"
                >
                  <div className="space-y-1 min-w-0">
                    <p className="font-mono text-xs font-semibold text-gray-900 break-all">
                      {u.defanged_url}
                    </p>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-gray-500">
                      <span>Domain: <strong className="text-gray-700">{u.domain}</strong></span>
                      <span>•</span>
                      <span>Scheme: <strong className="text-gray-700">{u.scheme}</strong></span>
                      {u.is_ip_address && (
                        <span className="rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700">
                          RAW IP ADDRESS
                        </span>
                      )}
                      {u.is_suspicious_tld && (
                        <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-800">
                          HIGH-RISK TLD
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="shrink-0">
                    <StatusBadge
                      variant={
                        u.reputation === 'clean'
                          ? 'clean'
                          : u.reputation === 'malicious'
                            ? 'malicious'
                            : u.reputation === 'suspicious'
                              ? 'suspicious'
                              : 'unknown'
                      }
                      label={u.reputation}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {/* Tab 3: RFC Headers */}
      {activeTab === 'headers' && (
        <SectionCard title="Full RFC Headers" icon={<FileSpreadsheet className="h-4 w-4" />}>
          {Object.keys(result.headers.raw_headers).length === 0 ? (
            <p className="text-sm text-gray-500">No raw headers dictionary recorded for this email.</p>
          ) : (
            <div className="rounded-lg border border-gray-200 overflow-hidden shadow-sm">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-50 border-b border-gray-100 text-gray-600 uppercase font-semibold">
                  <tr>
                    <th className="px-3.5 py-2.5 w-1/3">Header</th>
                    <th className="px-3.5 py-2.5">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 font-mono">
                  {Object.entries(result.headers.raw_headers).map(([k, v]) => (
                    <tr key={k} className="hover:bg-violet-50/20 transition-colors">
                      <td className="px-3.5 py-2 font-medium text-violet-700 break-all">{k}</td>
                      <td className="px-3.5 py-2 text-gray-700 break-all">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      )}

      {/* Tab 4: Attachments */}
      {activeTab === 'attachments' && (
        <SectionCard title={`Attachments (${result.attachments.length})`} icon={<Paperclip className="h-4 w-4" />}>
          {result.attachments.length === 0 ? (
            <p className="text-sm text-gray-500">No attachments were found in this email.</p>
          ) : (
            <div className="divide-y divide-gray-100 overflow-hidden rounded-lg border border-gray-200 bg-white">
              {result.attachments.map((att, i) => (
                <div key={i} className="p-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-gray-900 truncate">{att.filename}</p>
                      {att.is_executable && (
                        <span className="rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700">
                          EXECUTABLE
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500">
                      {(att.size_bytes / 1024).toFixed(1)} KB • {att.content_type}
                    </p>
                    <p className="font-mono text-[11px] text-gray-400 break-all">
                      SHA256: {att.sha256}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {/* Tab 5: Message Body */}
      {activeTab === 'body' && (
        <SectionCard title="Decoded Body Content" icon={<FileText className="h-4 w-4" />}>
          <div className="space-y-4">
            {result.body_plain && (
              <div className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Plain Text View
                </span>
                <pre className="rounded-lg bg-gray-50 border border-gray-200 p-4 text-xs font-mono text-gray-800 whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {result.body_plain}
                </pre>
              </div>
            )}

            {result.body_html && (
              <div className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                  Raw HTML Source
                </span>
                <pre className="rounded-lg bg-gray-50 border border-gray-200 p-4 text-xs font-mono text-gray-700 whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {result.body_html}
                </pre>
              </div>
            )}

            {!result.body_plain && !result.body_html && (
              <p className="text-sm text-gray-500">No body content was provided or decoded.</p>
            )}
          </div>
        </SectionCard>
      )}
    </div>
  )
}
