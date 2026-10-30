import { type FC } from 'react'
import { cn } from '../../shared/lib/utils'
import { type NormalizedVerdictTier } from './analysisNotificationStore'

interface RiskScoreIndicatorProps {
  score: number
  tier: NormalizedVerdictTier
  className?: string
}

export const RiskScoreIndicator: FC<RiskScoreIndicatorProps> = ({
  score,
  tier,
  className,
}) => {
  const boundedScore = Math.min(100, Math.max(0, Math.round(score)))

  const styles = {
    safe: {
      text: 'text-emerald-700',
      bar: 'bg-emerald-500',
      bg: 'bg-emerald-50 border-emerald-200',
      label: 'Low Risk',
    },
    medium: {
      text: 'text-amber-700',
      bar: 'bg-amber-500',
      bg: 'bg-amber-50 border-amber-200',
      label: 'Elevated Risk',
    },
    high: {
      text: 'text-rose-700',
      bar: 'bg-rose-500',
      bg: 'bg-rose-50 border-rose-200',
      label: 'Critical Danger',
    },
  }[tier]

  return (
    <div className={cn('rounded-xl border p-2.5', styles.bg, className)}>
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider">
          Risk Score
        </span>
        <div className="flex items-baseline gap-1">
          <span className={cn('text-lg font-extrabold tabular-nums tracking-tight', styles.text)}>
            {boundedScore}
          </span>
          <span className="text-[11px] font-semibold text-slate-400">/ 100</span>
        </div>
      </div>

      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200/80">
        <div
          className={cn('h-full rounded-full transition-all duration-500 ease-out', styles.bar)}
          style={{ width: `${boundedScore}%` }}
        />
      </div>
    </div>
  )
}
