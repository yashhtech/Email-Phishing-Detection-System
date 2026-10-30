import { type FC } from 'react'
import { AlertOctagon, AlertTriangle, ShieldCheck } from 'lucide-react'
import { cn } from '../../shared/lib/utils'
import {
  type NormalizedVerdictTier,
  getVerdictHeading,
} from './analysisNotificationStore'

interface AnalysisVerdictBadgeProps {
  tier: NormalizedVerdictTier
  verdictText?: string
  className?: string
}

export const AnalysisVerdictBadge: FC<AnalysisVerdictBadgeProps> = ({
  tier,
  verdictText,
  className,
}) => {
  const heading = getVerdictHeading(tier)

  const config = {
    safe: {
      icon: ShieldCheck,
      badgeText: verdictText || 'SAFE',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      iconContainer: 'bg-emerald-50 text-emerald-600 border-emerald-200',
      headingClass: 'text-emerald-950',
    },
    medium: {
      icon: AlertTriangle,
      badgeText: verdictText || 'MEDIUM RISK',
      badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
      iconContainer: 'bg-amber-50 text-amber-600 border-amber-200',
      headingClass: 'text-amber-950',
    },
    high: {
      icon: AlertOctagon,
      badgeText: verdictText || 'HIGH RISK',
      badgeClass: 'bg-rose-100 text-rose-900 border-rose-300',
      iconContainer: 'bg-rose-50 text-rose-600 border-rose-200',
      headingClass: 'text-rose-950',
    },
  }[tier]

  const Icon = config.icon

  return (
    <div className={cn('flex items-start gap-3', className)}>
      <div
        className={cn(
          'flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border shadow-2xs',
          config.iconContainer
        )}
      >
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase',
              config.badgeClass
            )}
          >
            {config.badgeText}
          </span>
        </div>
        <h3 className={cn('text-sm font-bold tracking-tight mt-1', config.headingClass)}>
          {heading}
        </h3>
      </div>
    </div>
  )
}
