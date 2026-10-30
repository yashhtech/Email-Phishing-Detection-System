import { type FC, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowRight, Mail, User, X } from 'lucide-react'
import { cn } from '../../shared/lib/utils'
import {
  classifyVerdictTier,
  useAnalysisNotificationStore,
} from './analysisNotificationStore'
import { AnalysisVerdictBadge } from './AnalysisVerdictBadge'
import { RecommendedActions } from './RecommendedActions'
import { RiskScoreIndicator } from './RiskScoreIndicator'
import { SecurityFindingsList } from './SecurityFindingsList'

const AUTO_DISMISS_SECONDS = 14

export const AnalysisResultToast: FC = () => {
  const navigate = useNavigate()
  const {
    activeNotification,
    errorNotification,
    dismissNotification,
    dismissError,
  } = useAnalysisNotificationStore()

  const [isPaused, setIsPaused] = useState(false)
  const [secondsRemaining, setSecondsRemaining] = useState(AUTO_DISMISS_SECONDS)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Reset countdown whenever a new notification arrives
  useEffect(() => {
    if (activeNotification) {
      setSecondsRemaining(AUTO_DISMISS_SECONDS)
      setIsPaused(false)
    }
  }, [activeNotification?.analysis_id])

  // Countdown timer with pause-on-hover support
  useEffect(() => {
    if (!activeNotification || isPaused) {
      if (timerRef.current) clearInterval(timerRef.current)
      return
    }

    timerRef.current = setInterval(() => {
      setSecondsRemaining((prev) => {
        if (prev <= 1) {
          dismissNotification()
          return 0
        }
        return prev - 1
      })
    }, 1000)

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [activeNotification, isPaused, dismissNotification])

  // Keyboard accessibility: dismiss on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (activeNotification) dismissNotification()
        if (errorNotification) dismissError()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [activeNotification, errorNotification, dismissNotification, dismissError])

  // Render error notification if present
  if (errorNotification && !activeNotification) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className="fixed top-4 right-4 sm:top-5 sm:right-5 z-50 max-w-md w-[calc(100vw-2rem)] sm:w-[420px] animate-in slide-in-from-top-4 fade-in duration-300"
      >
        <div className="overflow-hidden rounded-2xl border border-rose-200 bg-white p-4 shadow-2xl ring-1 ring-black/5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-2.5">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-rose-50 border border-rose-200 text-rose-600">
                <AlertCircle className="h-5 w-5" />
              </span>
              <div>
                <h4 className="text-sm font-bold text-rose-950">{errorNotification.title}</h4>
                <p className="text-xs text-rose-700 mt-0.5 leading-relaxed">
                  {errorNotification.message}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={dismissError}
              aria-label="Dismiss error"
              className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-3 flex justify-end">
            <button
              type="button"
              onClick={dismissError}
              className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors"
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (!activeNotification) {
    return null
  }

  const tier = classifyVerdictTier(
    activeNotification.severity,
    activeNotification.risk_score,
    activeNotification.verdict
  )

  const cardBorder = {
    safe: 'border-emerald-200/90 ring-emerald-500/10',
    medium: 'border-amber-200/90 ring-amber-500/10',
    high: 'border-rose-200/90 ring-rose-500/10',
  }[tier]

  const progressBg = {
    safe: 'bg-emerald-500',
    medium: 'bg-amber-500',
    high: 'bg-rose-500',
  }[tier]

  const progressPercent = Math.max(0, Math.min(100, (secondsRemaining / AUTO_DISMISS_SECONDS) * 100))

  const handleViewFullAnalysis = () => {
    const analysisId = activeNotification.analysis_id
    dismissNotification()
    navigate(`/analysis/${analysisId}`)
  }

  return (
    <aside
      role="alert"
      aria-live="polite"
      aria-label="Email threat analysis result"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      className={cn(
        'fixed top-4 right-4 sm:top-5 sm:right-5 z-50 max-w-md w-[calc(100vw-2rem)] sm:w-[440px]',
        'animate-in slide-in-from-top-4 fade-in duration-300'
      )}
    >
      <div
        className={cn(
          'relative overflow-hidden rounded-2xl bg-white border shadow-2xl ring-1',
          cardBorder
        )}
      >
        {/* Header bar */}
        <div className="p-4 sm:p-5 border-b border-slate-100 flex items-start justify-between gap-3">
          <AnalysisVerdictBadge
            tier={tier}
            verdictText={activeNotification.verdict}
            className="flex-1"
          />
          <button
            type="button"
            onClick={dismissNotification}
            aria-label="Close notification"
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content body */}
        <div className="p-4 sm:p-5 space-y-4 max-h-[calc(100vh-140px)] overflow-y-auto">
          {/* Email metadata: Subject & Sender */}
          <div className="rounded-xl bg-slate-50 border border-slate-200/70 p-3 space-y-1.5 text-xs">
            <div className="flex items-center gap-2 text-slate-500">
              <Mail className="h-3.5 w-3.5 shrink-0 text-slate-400" />
              <span className="font-semibold text-slate-700">Subject:</span>
              <span className="truncate text-slate-900 font-medium">
                {activeNotification.subject || '(No Subject)'}
              </span>
            </div>
            <div className="flex items-center gap-2 text-slate-500">
              <User className="h-3.5 w-3.5 shrink-0 text-slate-400" />
              <span className="font-semibold text-slate-700">Sender:</span>
              <span className="truncate font-mono text-[11px] text-slate-800">
                {activeNotification.sender || 'Unknown Sender'}
              </span>
            </div>
          </div>

          {/* Risk score */}
          <RiskScoreIndicator score={activeNotification.risk_score} tier={tier} />

          {/* Security findings & Checks */}
          <SecurityFindingsList
            tier={tier}
            explanation={activeNotification.explanation}
            findings={activeNotification.findings}
            securityChecks={activeNotification.security_checks}
            threatCategories={activeNotification.threat_categories}
          />

          {/* Recommended actions */}
          <RecommendedActions
            tier={tier}
            recommendations={activeNotification.recommendations}
          />
        </div>

        {/* Action buttons */}
        <div className="p-3 sm:px-5 sm:py-3.5 bg-slate-50/80 border-t border-slate-100 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={dismissNotification}
            className="rounded-xl px-3 py-2 text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-200/60 transition-colors"
          >
            Dismiss
          </button>

          <button
            type="button"
            onClick={handleViewFullAnalysis}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-xl px-4 py-2 text-xs font-bold shadow-xs transition-all duration-150',
              tier === 'high'
                ? 'bg-rose-600 text-white hover:bg-rose-700 active:scale-98'
                : tier === 'medium'
                ? 'bg-amber-600 text-white hover:bg-amber-700 active:scale-98'
                : 'bg-emerald-600 text-white hover:bg-emerald-700 active:scale-98'
            )}
          >
            <span>View Full Analysis</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Animated countdown progress bar */}
        <div className="h-1 w-full bg-slate-100 overflow-hidden">
          <div
            className={cn('h-full transition-all duration-1000 ease-linear', progressBg)}
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>
    </aside>
  )
}
