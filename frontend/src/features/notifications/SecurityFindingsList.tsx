import { type FC } from 'react'
import { CheckCircle2, AlertCircle, Info, Link2, Paperclip } from 'lucide-react'
import { cn } from '../../shared/lib/utils'
import { type NormalizedVerdictTier } from './analysisNotificationStore'

interface SecurityFindingsListProps {
  tier: NormalizedVerdictTier
  explanation?: string | null
  findings?: string[]
  securityChecks?: {
    spf?: string
    dkim?: string
    dmarc?: string
    urls_analyzed?: number
    attachments_analyzed?: number
    [key: string]: unknown
  }
  threatCategories?: string[]
  className?: string
}

function authBadgeClass(status?: string): string {
  const s = (status || '').toLowerCase()
  if (s === 'pass' || s === 'success') {
    return 'bg-emerald-50 text-emerald-700 border-emerald-200'
  }
  if (s === 'fail' || s === 'failed') {
    return 'bg-rose-50 text-rose-700 border-rose-200'
  }
  return 'bg-slate-50 text-slate-600 border-slate-200'
}

export const SecurityFindingsList: FC<SecurityFindingsListProps> = ({
  tier,
  explanation,
  findings = [],
  securityChecks,
  threatCategories = [],
  className,
}) => {
  const topFindings = findings.slice(0, 3)

  return (
    <div className={cn('space-y-3', className)}>
      {/* Short AI / Engine Explanation */}
      {explanation && (
        <div className="rounded-xl bg-slate-50 border border-slate-200/80 p-2.5 text-xs text-slate-700 leading-relaxed">
          <div className="flex items-start gap-1.5">
            <Info className="h-3.5 w-3.5 text-slate-500 shrink-0 mt-0.5" />
            <p className="line-clamp-3">{explanation}</p>
          </div>
        </div>
      )}

      {/* Top 3 Findings */}
      {topFindings.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
            {tier === 'safe' ? 'Key Security Findings' : 'Why Flagged'}
          </p>
          <ul className="space-y-1">
            {topFindings.map((finding, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 text-xs text-slate-700 leading-tight"
              >
                {tier === 'safe' ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle
                    className={cn(
                      'h-3.5 w-3.5 shrink-0 mt-0.5',
                      tier === 'high' ? 'text-rose-500' : 'text-amber-500'
                    )}
                  />
                )}
                <span className="line-clamp-2">{finding}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Security Checks & Threat Categories Summary */}
      <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 text-[10px]">
        {securityChecks && (
          <>
            {securityChecks.spf && (
              <span
                className={cn(
                  'rounded-md border px-1.5 py-0.5 font-semibold uppercase',
                  authBadgeClass(securityChecks.spf)
                )}
              >
                SPF: {securityChecks.spf}
              </span>
            )}
            {securityChecks.dkim && (
              <span
                className={cn(
                  'rounded-md border px-1.5 py-0.5 font-semibold uppercase',
                  authBadgeClass(securityChecks.dkim)
                )}
              >
                DKIM: {securityChecks.dkim}
              </span>
            )}
            {securityChecks.dmarc && (
              <span
                className={cn(
                  'rounded-md border px-1.5 py-0.5 font-semibold uppercase',
                  authBadgeClass(securityChecks.dmarc)
                )}
              >
                DMARC: {securityChecks.dmarc}
              </span>
            )}
            {typeof securityChecks.urls_analyzed === 'number' && securityChecks.urls_analyzed > 0 && (
              <span className="rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-medium text-slate-600 flex items-center gap-1">
                <Link2 className="h-2.5 w-2.5 text-slate-400" />
                {securityChecks.urls_analyzed} {securityChecks.urls_analyzed === 1 ? 'URL' : 'URLs'}
              </span>
            )}
            {typeof securityChecks.attachments_analyzed === 'number' &&
              securityChecks.attachments_analyzed > 0 && (
                <span className="rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-medium text-slate-600 flex items-center gap-1">
                  <Paperclip className="h-2.5 w-2.5 text-slate-400" />
                  {securityChecks.attachments_analyzed}{' '}
                  {securityChecks.attachments_analyzed === 1 ? 'file' : 'files'}
                </span>
              )}
          </>
        )}

        {/* Threat Categories Badges */}
        {threatCategories.map((cat, idx) => (
          <span
            key={idx}
            className="rounded-md border border-slate-200 bg-slate-100 px-1.5 py-0.5 font-semibold capitalize text-slate-700"
          >
            {cat.replace(/_/g, ' ')}
          </span>
        ))}
      </div>
    </div>
  )
}
