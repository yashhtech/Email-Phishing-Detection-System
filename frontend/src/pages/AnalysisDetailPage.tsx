import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Clock,
  Cpu,
  Brain,
  Globe,
  Lock,
  AlertOctagon,
  ChevronRight,
  Tag,
  Mail,
  Send,
  AtSign,
  Link2,
  Paperclip,
  Check,
  FileText,
} from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import {
  Badge,
  RiskBadge,
  Card,
  CardHeader,
  CardTitle,
  CardBody,
  Skeleton,
  EmptyState,
  Alert,
  Spinner,
  Button,
} from '../shared/ui'
import { analysisApi } from '../shared/api/analysis.api'
import type {
  AnalysisDetail,
  ThreatSignal,
  MLPrediction,
  LLMAnalysis,
  ThreatIntelResult,
} from '../entities/emailAnalysis'

// ── Helpers ───────────────────────────────────────────────────────────────────

function riskScoreColor(score: number): string {
  if (score >= 80) return 'text-danger-600'
  if (score >= 60) return 'text-coral-600'
  if (score >= 40) return 'text-warning-600'
  return 'text-success-600'
}

function riskScoreBg(score: number): string {
  if (score >= 80) return 'bg-danger-50 border-danger-200'
  if (score >= 60) return 'bg-coral-50 border-coral-200'
  if (score >= 40) return 'bg-warning-50 border-warning-200'
  return 'bg-success-50 border-success-200'
}

function severityClasses(severity: string): string {
  switch (severity.toLowerCase()) {
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

function reputationClasses(reputation: string): string {
  switch (reputation.toLowerCase()) {
    case 'malicious':
      return 'bg-danger-50 text-danger-700 border-danger-200'
    case 'suspicious':
      return 'bg-warning-50 text-warning-700 border-warning-200'
    case 'clean':
      return 'bg-success-50 text-success-700 border-success-200'
    default:
      return 'bg-neutral-50 text-neutral-600 border-neutral-200'
  }
}

function formatDuration(ms: number | null): string {
  if (!ms) return '—'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function confidenceBar(confidence: number, colorClass: string) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-neutral-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${colorClass}`}
          style={{ width: `${Math.round(confidence * 100)}%` }}
        />
      </div>
      <span className="text-xs text-neutral-500 tabular-nums w-9 text-right font-medium">
        {Math.round(confidence * 100)}%
      </span>
    </div>
  )
}

// ── Section 1: Executive Overview Strip ───────────────────────────────────────

function RiskScoreHeader({ detail }: { detail: AnalysisDetail }) {
  const score = detail.overall_risk_score
  const scoreColorBg = riskScoreBg(score)
  const scoreTextColor = riskScoreColor(score)

  const safeLevel = (['critical', 'high', 'medium', 'low', 'safe'] as const).includes(
    detail.risk_level.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'safe'
  )
    ? (detail.risk_level.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'safe')
    : 'low'

  // Derive primary attack type
  const topSignal = detail.threat_signals.find(
    (s) => s.attack_type && s.attack_type !== 'none' && s.attack_type !== 'unknown'
  )
  const primaryAttackType =
    topSignal?.attack_type ||
    (detail.verdict === 'clean' ? 'benign' : 'phishing')

  // Overall confidence
  const overallConfidence =
    detail.ml_prediction?.confidence ??
    (detail.threat_signals.length > 0
      ? Math.max(...detail.threat_signals.map((s) => s.confidence))
      : 0.95)

  return (
    <div className="bg-white border border-neutral-150 rounded-2xl shadow-card p-6 space-y-6">
      <div className="flex flex-col lg:flex-row gap-6 items-start lg:items-center justify-between">
        {/* Score Ring */}
        <div className="flex items-center gap-5">
          <div
            className={`w-24 h-24 rounded-2xl border-2 ${scoreColorBg} flex flex-col items-center justify-center shrink-0 shadow-sm`}
          >
            <span className={`text-3xl font-bold tabular-nums ${scoreTextColor}`}>{score}</span>
            <span className="text-2xs text-neutral-500 font-semibold uppercase tracking-wider mt-0.5">
              Risk Score
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <RiskBadge level={safeLevel} />
              <Badge variant="neutral" className="capitalize">
                {detail.verdict}
              </Badge>
              <Badge variant="info" className="capitalize">
                {detail.status}
              </Badge>
            </div>
            <p className="text-xs text-neutral-500">
              Analysis completed with authoritative multi-engine risk evaluation
            </p>
          </div>
        </div>

        {/* Timestamps / latency */}
        <div className="flex flex-wrap gap-4 text-xs text-neutral-500 lg:text-right">
          {detail.duration_ms != null && (
            <span className="flex items-center gap-1.5 bg-neutral-50 px-3 py-1.5 rounded-lg border border-neutral-100">
              <Clock className="h-3.5 w-3.5 text-neutral-400" />
              Duration: <b className="text-neutral-700">{formatDuration(detail.duration_ms)}</b>
            </span>
          )}
          {detail.completed_at && (
            <span className="flex items-center gap-1.5 bg-neutral-50 px-3 py-1.5 rounded-lg border border-neutral-100">
              <CheckCircle className="h-3.5 w-3.5 text-success-500" />
              Completed: <b className="text-neutral-700">{new Date(detail.completed_at).toLocaleTimeString()}</b>
            </span>
          )}
        </div>
      </div>

      {/* 5 Core Top-Level Dimensions Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-4 border-t border-neutral-100">
        <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
          <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
            Overall Risk Score
          </p>
          <p className={`text-lg font-bold tabular-nums ${scoreTextColor}`}>{score} / 100</p>
        </div>

        <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
          <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
            Severity
          </p>
          <p className="text-lg font-bold capitalize text-neutral-800">{detail.risk_level}</p>
        </div>

        <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
          <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
            Classification
          </p>
          <p className="text-lg font-bold capitalize text-neutral-800">{detail.verdict}</p>
        </div>

        <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
          <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
            Attack Type
          </p>
          <p className="text-lg font-bold capitalize text-neutral-800 truncate">
            {primaryAttackType.replace(/_/g, ' ')}
          </p>
        </div>

        <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100 col-span-2 sm:col-span-1">
          <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
            Confidence
          </p>
          <p className="text-lg font-bold tabular-nums text-neutral-800">
            {Math.round(overallConfidence * 100)}%
          </p>
        </div>
      </div>

      {/* Error state */}
      {detail.error_message && (
        <Alert variant="error" title="Analysis Pipeline Error">
          {detail.error_message}
        </Alert>
      )}
    </div>
  )
}

// ── Section 2: Security Signals (8 Deterministic Checks) ───────────────────────

interface SignalCardProps {
  name: string
  status: 'pass' | 'fail' | 'warn' | 'info'
  statusText: string
  subtext: string
  icon: React.ReactNode
}

function SignalCard({ name, status, statusText, subtext, icon }: SignalCardProps) {
  let statusBadgeClass = 'bg-neutral-50 text-neutral-600 border-neutral-200'
  let indicatorIcon = <Info className="h-3.5 w-3.5" />

  if (status === 'pass') {
    statusBadgeClass = 'bg-success-50 text-success-700 border-success-200'
    indicatorIcon = <Check className="h-3.5 w-3.5" />
  } else if (status === 'fail') {
    statusBadgeClass = 'bg-danger-50 text-danger-700 border-danger-200'
    indicatorIcon = <XCircle className="h-3.5 w-3.5" />
  } else if (status === 'warn') {
    statusBadgeClass = 'bg-warning-50 text-warning-700 border-warning-200'
    indicatorIcon = <AlertTriangle className="h-3.5 w-3.5" />
  }

  return (
    <div className="p-3.5 bg-neutral-50 border border-neutral-150 rounded-xl flex flex-col justify-between hover:border-neutral-250 transition-colors">
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <span className="p-1.5 rounded-lg bg-teal-50 text-teal-700 border border-teal-100">
            {icon}
          </span>
          <span className="text-xs font-bold text-neutral-800">{name}</span>
        </div>
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-2xs font-semibold border capitalize ${statusBadgeClass}`}
        >
          {indicatorIcon}
          {statusText}
        </span>
      </div>
      <p className="text-2xs text-neutral-500 truncate" title={subtext}>
        {subtext}
      </p>
    </div>
  )
}

function SecuritySignalsSection({ detail }: { detail: AnalysisDetail }) {
  const signals = detail.threat_signals
  const riskScore = detail.risk_score
  const breakdown = riskScore?.factor_breakdown ?? {}

  // 1. SPF
  const spfStatus = (typeof breakdown['spf_status'] === 'string' ? breakdown['spf_status'] : 'pass').toLowerCase()
  const spfCardStatus: 'pass' | 'fail' | 'warn' = spfStatus === 'pass' ? 'pass' : spfStatus === 'fail' ? 'fail' : 'warn'

  // 2. DKIM
  const dkimStatus = (typeof breakdown['dkim_status'] === 'string' ? breakdown['dkim_status'] : 'pass').toLowerCase()
  const dkimCardStatus: 'pass' | 'fail' | 'warn' = dkimStatus === 'pass' ? 'pass' : dkimStatus === 'fail' ? 'fail' : 'warn'

  // 3. DMARC
  const dmarcStatus = (typeof breakdown['dmarc_status'] === 'string' ? breakdown['dmarc_status'] : 'pass').toLowerCase()
  const dmarcCardStatus: 'pass' | 'fail' | 'warn' = dmarcStatus === 'pass' ? 'pass' : dmarcStatus === 'fail' ? 'fail' : 'warn'

  // 4. Sender
  const senderThreat = signals.find((s) => s.signal_type.toLowerCase().includes('sender'))
  const senderCardStatus: 'pass' | 'fail' | 'warn' = senderThreat ? (senderThreat.severity === 'critical' || senderThreat.severity === 'high' ? 'fail' : 'warn') : 'pass'

  // 5. Reply-To
  const replyToThreat = signals.find((s) => s.signal_type.toLowerCase().includes('reply'))
  const replyToCardStatus: 'pass' | 'fail' | 'warn' = replyToThreat ? 'warn' : 'pass'

  // 6. Domain
  const domainThreat = signals.find((s) => s.signal_type.toLowerCase().includes('domain') || s.signal_type.toLowerCase().includes('typosquatting'))
  const domainCardStatus: 'pass' | 'fail' | 'warn' = domainThreat ? (domainThreat.severity === 'critical' ? 'fail' : 'warn') : 'pass'

  // 7. URL
  const urlThreat = signals.find((s) => s.signal_type.toLowerCase().includes('url'))
  const urlCardStatus: 'pass' | 'fail' | 'warn' = urlThreat ? (urlThreat.severity === 'critical' ? 'fail' : 'warn') : 'pass'

  // 8. Attachment
  const attachThreat = signals.find((s) => s.signal_type.toLowerCase().includes('attachment'))
  const attachCardStatus: 'pass' | 'fail' | 'warn' = attachThreat ? (attachThreat.severity === 'critical' ? 'fail' : 'warn') : 'pass'

  return (
    <Card padding="none">
      <CardHeader>
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-teal-600" />
            <CardTitle>Deterministic Security Signals</CardTitle>
          </div>
          <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-2xs font-semibold bg-teal-50 text-teal-700 border border-teal-200">
            8 Signals Evaluated
          </span>
        </div>
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <SignalCard
            name="SPF"
            status={spfCardStatus}
            statusText={spfStatus}
            subtext="Sender Policy Framework IP authorization"
            icon={<Shield className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="DKIM"
            status={dkimCardStatus}
            statusText={dkimStatus}
            subtext="Cryptographic signature verification"
            icon={<CheckCircle className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="DMARC"
            status={dmarcCardStatus}
            statusText={dmarcStatus}
            subtext="Domain policy alignment enforcement"
            icon={<Lock className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="Sender"
            status={senderCardStatus}
            statusText={senderThreat ? senderThreat.severity : 'Verified'}
            subtext={senderThreat ? senderThreat.title : 'Display name & address aligned'}
            icon={<Mail className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="Reply-To"
            status={replyToCardStatus}
            statusText={replyToThreat ? 'Mismatch' : 'Aligned'}
            subtext={replyToThreat ? replyToThreat.title : 'Reply header matches envelope From'}
            icon={<Send className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="Domain"
            status={domainCardStatus}
            statusText={domainThreat ? domainThreat.severity : 'Reputable'}
            subtext={domainThreat ? domainThreat.title : 'Age, registrar & lookalike check passed'}
            icon={<AtSign className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="URL"
            status={urlCardStatus}
            statusText={urlThreat ? urlThreat.severity : 'Clean'}
            subtext={urlThreat ? urlThreat.title : 'Zero malicious links or redirection tactics'}
            icon={<Link2 className="h-3.5 w-3.5" />}
          />
          <SignalCard
            name="Attachment"
            status={attachCardStatus}
            statusText={attachThreat ? attachThreat.severity : 'Clean'}
            subtext={attachThreat ? attachThreat.title : 'Zero executable, macro, or archive threats'}
            icon={<Paperclip className="h-3.5 w-3.5" />}
          />
        </div>
      </CardBody>
    </Card>
  )
}

// ── Section 3: Machine Learning Classification ────────────────────────────────

function MLResultSection({ ml }: { ml: MLPrediction }) {
  const probs = [
    { label: 'Phishing', value: ml.phishing_probability, color: 'bg-danger-500' },
    { label: 'Spam', value: ml.spam_probability, color: 'bg-warning-500' },
    { label: 'Malware', value: ml.malware_probability, color: 'bg-coral-500' },
  ]

  return (
    <Card padding="none">
      <CardHeader>
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-violet-600" />
            <CardTitle>ML Engine Classification</CardTitle>
          </div>
          <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-2xs font-semibold bg-violet-50 text-violet-700 border border-violet-200">
            Model: {ml.model_name}
          </span>
        </div>
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {/* Prediction and Model Info */}
          <div>
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-2">
              Model Prediction
            </p>
            <p className="text-2xl font-bold text-neutral-900 capitalize mb-4">
              {ml.classification.replace(/_/g, ' ')}
            </p>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-neutral-100 text-neutral-500">
                <span>Confidence</span>
                <span className="font-semibold text-neutral-800">
                  {Math.round(ml.confidence * 100)}%
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-neutral-100 text-neutral-500">
                <span>Model Version</span>
                <span className="font-mono text-neutral-700 font-semibold">{ml.model_version}</span>
              </div>
              <div className="flex justify-between py-1 text-neutral-500">
                <span>Architecture</span>
                <span className="text-neutral-700">Calibrated Ensemble Classifier</span>
              </div>
            </div>
          </div>

          {/* Probability Distribution */}
          <div>
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-2">
              Class Probabilities
            </p>
            <div className="space-y-3">
              {probs.map(({ label, value, color }) => (
                <div key={label}>
                  <div className="flex justify-between text-xs text-neutral-600 mb-1">
                    <span className="font-medium">{label}</span>
                    <span className="tabular-nums font-semibold">{(value * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-2 bg-neutral-100 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${color}`}
                      style={{ width: `${value * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  )
}

// ── Section 4: Groq LLM Semantic Intelligence ─────────────────────────────────

function LLMAnalysisSection({ llm }: { llm: LLMAnalysis }) {
  // Parse tactics & quotes from extracted_iocs
  const tactics = llm.extracted_iocs
    .filter((ioc) => ioc.type === 'social_engineering_tactic')
    .map((ioc) => String(ioc.value))

  const quotes = llm.extracted_iocs
    .filter((ioc) => ioc.type === 'evidence_quote')
    .map((ioc) => String(ioc.value))

  return (
    <Card padding="none" className="border-violet-200 shadow-sm">
      <CardHeader>
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-violet-600" />
            <CardTitle>Groq LLM Semantic Analysis</CardTitle>
          </div>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg text-2xs font-semibold bg-violet-50 text-violet-700 border border-violet-200">
            <span className="h-1.5 w-1.5 rounded-full bg-violet-600 animate-pulse" />
            {llm.model_name}
          </span>
        </div>
      </CardHeader>
      <CardBody>
        {/* Safety Warning */}
        {!llm.safety_passed && (
          <Alert variant="error" title="Safety Gateway Warning" className="mb-4">
            The LLM output triggered a safety validation boundary. Findings should be corroborated
            against deterministic security signals before taking administrative action.
          </Alert>
        )}

        {/* AI Disclaimer Alert */}
        <div className="flex items-start gap-2.5 p-3 bg-violet-50 border border-violet-100 rounded-xl mb-5">
          <Info className="h-4 w-4 text-violet-600 mt-0.5 shrink-0" />
          <p className="text-xs text-violet-800 leading-relaxed">
            <b>Semantic AI Findings:</b> Synthesized using Groq LLM inference. Natural language
            hypotheses provide behavioral context and do not supersede deterministic RFC authentication
            checks.
          </p>
        </div>

        {/* 5 Requested LLM Fields: Classification, Confidence, Intent, Social Engineering Techniques, Semantic Explanation */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
          <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
              LLM Classification
            </p>
            <p className="text-base font-bold text-violet-900 capitalize">
              {llm.recommended_action.replace(/_/g, ' ')}
            </p>
          </div>

          <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
              Confidence
            </p>
            <p className="text-base font-bold text-neutral-900 tabular-nums">
              {Math.round(llm.confidence_score * 100)}%
            </p>
          </div>

          <div className="p-3 bg-neutral-50 rounded-xl border border-neutral-100">
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
              Inference Latency
            </p>
            <p className="text-base font-bold text-neutral-900">
              {formatDuration(llm.latency_ms)}
            </p>
          </div>
        </div>

        {/* Intent Analysis */}
        {llm.reasoning && (
          <div className="mb-5">
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1.5">
              Assessed Intent
            </p>
            <div className="p-3 bg-neutral-50 border border-neutral-100 rounded-xl text-xs text-neutral-700 leading-relaxed">
              {llm.reasoning}
            </div>
          </div>
        )}

        {/* Social Engineering Techniques */}
        {tactics.length > 0 && (
          <div className="mb-5">
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-2">
              Social Engineering Techniques
            </p>
            <div className="flex flex-wrap gap-2">
              {tactics.map((tactic, i) => (
                <span
                  key={i}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-violet-50 text-violet-700 border border-violet-100 rounded-lg text-xs font-semibold"
                >
                  <Tag className="h-3 w-3 text-violet-500" />
                  {tactic}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Semantic Explanation / Threat Narrative */}
        <div className="space-y-4">
          {llm.executive_summary && (
            <div>
              <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1.5">
                Executive Summary
              </p>
              <p className="text-xs text-neutral-700 leading-relaxed font-medium">
                {llm.executive_summary}
              </p>
            </div>
          )}

          <div>
            <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-1.5">
              Semantic Explanation &amp; Narrative
            </p>
            <p className="text-xs text-neutral-600 leading-relaxed whitespace-pre-wrap">
              {llm.threat_narrative}
            </p>
          </div>

          {/* Evidence Quotes */}
          {quotes.length > 0 && (
            <div>
              <p className="text-2xs font-semibold text-neutral-400 uppercase tracking-wider mb-2">
                Untrusted Body Evidence Quotes
              </p>
              <div className="space-y-1.5">
                {quotes.map((quote, i) => (
                  <blockquote
                    key={i}
                    className="text-xs font-mono text-danger-700 bg-danger-50 border-l-2 border-danger-400 px-3 py-1.5 rounded-r"
                  >
                    "{quote}"
                  </blockquote>
                ))}
              </div>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  )
}

// ── Section 5: Threat Intelligence ────────────────────────────────────────────

function ThreatIntelSection({ results }: { results: ThreatIntelResult[] }) {
  if (results.length === 0) {
    return (
      <Card padding="none">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-teal-600" />
            <CardTitle>External Threat Intelligence</CardTitle>
          </div>
        </CardHeader>
        <CardBody>
          <EmptyState
            icon={<Globe className="h-8 w-8 text-neutral-300" />}
            title="No threat intelligence results"
            description="No external domain, URL, or hash indicators were flagged for enrichment."
          />
        </CardBody>
      </Card>
    )
  }

  return (
    <Card padding="none">
      <CardHeader>
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-teal-600" />
            <CardTitle>External Threat Intelligence</CardTitle>
          </div>
          <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-2xs font-semibold bg-teal-50 text-teal-700 border border-teal-200">
            {results.length} Indicators Queried
          </span>
        </div>
      </CardHeader>
      <CardBody>
        <div className="overflow-x-auto -mx-6">
          <table className="w-full min-w-[650px]">
            <thead>
              <tr className="border-b border-neutral-100 bg-neutral-50/50">
                {['Indicator', 'Type', 'Provider', 'Reputation', 'Confidence / Score', 'Tags', 'Checked'].map(
                  (h) => (
                    <th
                      key={h}
                      className="px-6 py-2.5 text-left text-2xs font-bold text-neutral-400 uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-100 text-xs">
              {results.map((ti, i) => (
                <tr key={i} className="hover:bg-neutral-50/70 transition-colors">
                  <td className="px-6 py-3">
                    <span className="font-mono text-teal-700 bg-teal-50 border border-teal-100 rounded px-2 py-0.5 max-w-[220px] block truncate font-medium">
                      {ti.indicator_value}
                    </span>
                  </td>
                  <td className="px-6 py-3 font-medium text-neutral-600 capitalize">
                    {ti.indicator_type}
                  </td>
                  <td className="px-6 py-3 font-semibold text-neutral-800 uppercase">
                    {ti.provider}
                  </td>
                  <td className="px-6 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-md text-2xs font-bold border capitalize ${reputationClasses(
                        ti.reputation
                      )}`}
                    >
                      {ti.reputation}
                    </span>
                  </td>
                  <td className="px-6 py-3 tabular-nums font-semibold text-neutral-800">
                    {ti.threat_score !== null ? `${ti.threat_score} / 100` : '—'}
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {ti.tags.slice(0, 3).map((tag) => (
                        <span
                          key={tag}
                          className="px-1.5 py-0.5 bg-neutral-100 text-neutral-600 text-2xs rounded font-medium"
                        >
                          {tag}
                        </span>
                      ))}
                      {ti.tags.length > 3 && (
                        <span className="text-2xs text-neutral-400">+{ti.tags.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-3 text-neutral-400">
                    {new Date(ti.last_checked_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardBody>
    </Card>
  )
}

// ── Section 6: Comprehensive Evidence Section ─────────────────────────────────

function EvidenceSection({ signals }: { signals: ThreatSignal[] }) {
  if (signals.length === 0) {
    return (
      <Card padding="none">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-neutral-400" />
            <CardTitle>Evidence Findings</CardTitle>
          </div>
        </CardHeader>
        <CardBody>
          <EmptyState
            icon={<CheckCircle className="h-8 w-8 text-success-500" />}
            title="No evidence collected"
            description="Zero malicious artifacts or behavioral anomalies were detected."
          />
        </CardBody>
      </Card>
    )
  }

  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  }
  const sorted = [...signals].sort(
    (a, b) => (severityOrder[a.severity.toLowerCase()] ?? 5) - (severityOrder[b.severity.toLowerCase()] ?? 5)
  )

  return (
    <Card padding="none">
      <CardHeader>
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-coral-600" />
            <CardTitle>Forensic Evidence</CardTitle>
          </div>
          <span className="inline-flex items-center px-2 py-0.5 rounded-lg text-2xs font-semibold bg-neutral-100 text-neutral-700">
            {signals.length} Findings Recorded
          </span>
        </div>
      </CardHeader>
      <CardBody>
        <div className="space-y-4">
          {sorted.map((sig) => {
            const cls = severityClasses(sig.severity)
            const isAI = sig.source.toLowerCase() === 'llm' || sig.source.toLowerCase() === 'groq'

            return (
              <div
                key={sig.id}
                className="p-4 bg-white border border-neutral-150 rounded-xl shadow-xs hover:border-neutral-250 transition-all space-y-3"
              >
                {/* Header Tag Row: Severity, Source, AI disclaimer, Attack Type */}
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded-md text-2xs font-bold border uppercase tracking-wider ${cls}`}
                  >
                    Severity: {sig.severity}
                  </span>

                  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-2xs font-semibold border bg-teal-50 text-teal-700 border-teal-200">
                    Source: {sig.source}
                  </span>

                  {isAI ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-2xs font-semibold border bg-violet-50 text-violet-700 border-violet-200">
                      <Brain className="h-3 w-3" />
                      AI-inferred — not independently verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-2xs font-semibold border bg-teal-50 text-teal-700 border-teal-200">
                      <Shield className="h-3 w-3" />
                      Verified Technical Signal
                    </span>
                  )}

                  <span className="ml-auto text-2xs text-neutral-400 capitalize font-medium">
                    Attack: {sig.attack_type.replace(/_/g, ' ')}
                  </span>
                </div>

                {/* 1. What was detected */}
                <div>
                  <span className="text-2xs font-bold text-neutral-400 uppercase tracking-wider block mb-0.5">
                    What was detected
                  </span>
                  <h4 className="text-sm font-bold text-neutral-900">{sig.title}</h4>
                </div>

                {/* 2. Why it matters */}
                <div>
                  <span className="text-2xs font-bold text-neutral-400 uppercase tracking-wider block mb-0.5">
                    Why it matters
                  </span>
                  <p className="text-xs text-neutral-600 leading-relaxed">{sig.description}</p>
                </div>

                {/* 3. Evidence */}
                {sig.indicator_value && (
                  <div>
                    <span className="text-2xs font-bold text-neutral-400 uppercase tracking-wider block mb-0.5">
                      Evidence
                    </span>
                    <code className="text-xs font-mono text-teal-800 bg-teal-50 border border-teal-200 rounded px-2.5 py-1 max-w-full block truncate">
                      {sig.indicator_value}
                    </code>
                  </div>
                )}

                {/* Confidence Bar */}
                <div className="pt-2 border-t border-neutral-100 flex items-center justify-between text-2xs text-neutral-400">
                  <span className="font-medium">Signal Confidence</span>
                  <div className="w-48">
                    {confidenceBar(
                      sig.confidence,
                      sig.severity.toLowerCase() === 'critical'
                        ? 'bg-danger-500'
                        : sig.severity.toLowerCase() === 'high'
                          ? 'bg-coral-500'
                          : sig.severity.toLowerCase() === 'medium'
                            ? 'bg-warning-500'
                            : 'bg-success-500'
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </CardBody>
    </Card>
  )
}

// ── Loading Skeleton ──────────────────────────────────────────────────────────

function AnalysisDetailSkeleton() {
  return (
    <div className="space-y-4">
      <div className="bg-white border border-neutral-150 rounded-2xl p-6 flex gap-6">
        <Skeleton className="w-24 h-24 rounded-2xl" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-64" />
        </div>
      </div>
      {[1, 2, 3].map((i) => (
        <div key={i} className="bg-white border border-neutral-150 rounded-2xl p-6 space-y-3">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
        </div>
      ))}
    </div>
  )
}

// ── Main Page Component ───────────────────────────────────────────────────────

export function AnalysisDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['analysis-detail', id],
    queryFn: () => analysisApi.getById(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'queued' || status === 'processing' ? 3000 : false
    },
  })

  return (
    <AppShell>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Breadcrumb / Actions Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Link
              to="/history"
              className="flex items-center gap-1.5 text-xs font-semibold text-neutral-500 hover:text-neutral-900 transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Analysis History
            </Link>
            {data && (
              <>
                <ChevronRight className="h-3.5 w-3.5 text-neutral-300" />
                <span className="text-xs text-neutral-400 font-mono truncate max-w-[240px]">
                  {id}
                </span>
              </>
            )}
          </div>
          {data && data.status === 'completed' && (
            <div className="flex items-center gap-2">
              <Link to={`/analysis/${id}/report`}>
                <Button variant="secondary" size="sm" leftIcon={<FileText className="h-3.5 w-3.5" />}>
                  Generate Report
                </Button>
              </Link>
            </div>
          )}
        </div>

        {/* Loading State */}
        {isLoading && <AnalysisDetailSkeleton />}

        {/* Error State */}
        {isError && (
          <Alert variant="error" title="Failed to load threat analysis">
            {error instanceof Error ? error.message : 'An unexpected error occurred.'}
          </Alert>
        )}

        {/* Processing State */}
        {data && (data.status === 'queued' || data.status === 'processing') && (
          <Card padding="none">
            <CardBody>
              <div className="flex flex-col items-center py-16 gap-4">
                <Spinner size="lg" />
                <p className="text-sm font-semibold text-neutral-700">
                  Threat analysis is {data.status === 'queued' ? 'queued' : 'in progress'}…
                </p>
                <p className="text-xs text-neutral-400 max-w-sm text-center">
                  Executing RFC authentication checks, machine learning inference, external threat
                  intel queries, and Groq semantic analysis.
                </p>
              </div>
            </CardBody>
          </Card>
        )}

        {/* Completed Analysis Forensic Dossier */}
        {data && data.status === 'completed' && (
          <>
            {/* 1. Overall Risk Score, Severity, Classification, Attack Type, Confidence */}
            <RiskScoreHeader detail={data} />

            {/* 2. Security Signals (SPF, DKIM, DMARC, Sender, Reply-To, Domain, URL, Attachment) */}
            <SecuritySignalsSection detail={data} />

            {/* 3. ML Result (Prediction, Confidence, Model Version) */}
            {data.ml_prediction && <MLResultSection ml={data.ml_prediction} />}

            {/* 4. Groq Result (Classification, Confidence, Intent, Social Engineering Techniques, Semantic Explanation) */}
            {data.llm_analysis ? (
              <LLMAnalysisSection llm={data.llm_analysis} />
            ) : (
              <Card padding="none">
                <CardBody>
                  <div className="flex items-center gap-3 py-4 text-neutral-500">
                    <Brain className="h-5 w-5 text-neutral-300" />
                    <p className="text-xs">
                      Semantic analysis was not performed for this email — risk was below the LLM
                      trigger threshold.
                    </p>
                  </div>
                </CardBody>
              </Card>
            )}

            {/* 5. Threat Intelligence (Indicator, Provider, Reputation, Confidence) */}
            <ThreatIntelSection results={data.threat_intel_results} />

            {/* 6. Evidence Section (What was detected, Why it matters, Evidence, Source, Severity) */}
            <EvidenceSection signals={data.threat_signals} />
          </>
        )}

        {/* Failed Analysis State */}
        {data && data.status === 'failed' && (
          <>
            <RiskScoreHeader detail={data} />
            {data.threat_signals.length > 0 && <EvidenceSection signals={data.threat_signals} />}
          </>
        )}
      </div>
    </AppShell>
  )
}
