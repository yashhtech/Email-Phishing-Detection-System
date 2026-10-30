import { type FC } from 'react'
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react'
import { cn } from '../../shared/lib/utils'
import {
  type NormalizedVerdictTier,
  getDefaultRecommendation,
} from './analysisNotificationStore'

interface RecommendedActionsProps {
  tier: NormalizedVerdictTier
  recommendations?: string[]
  className?: string
}

export const RecommendedActions: FC<RecommendedActionsProps> = ({
  tier,
  recommendations = [],
  className,
}) => {
  const defaultRec = getDefaultRecommendation(tier)
  const displayRecs = recommendations.length > 0 ? recommendations : [defaultRec]

  const styles = {
    safe: {
      container: 'bg-emerald-50/70 border-emerald-200/90 text-emerald-900',
      icon: ShieldCheck,
      iconColor: 'text-emerald-600',
    },
    medium: {
      container: 'bg-amber-50/70 border-amber-200/90 text-amber-950',
      icon: AlertTriangle,
      iconColor: 'text-amber-600',
    },
    high: {
      container: 'bg-rose-50/70 border-rose-200/90 text-rose-950',
      icon: ShieldAlert,
      iconColor: 'text-rose-600',
    },
  }[tier]

  const Icon = styles.icon

  return (
    <div className={cn('rounded-xl border p-2.5', styles.container, className)}>
      <div className="flex items-start gap-2">
        <Icon className={cn('h-4 w-4 shrink-0 mt-0.5', styles.iconColor)} />
        <div className="min-w-0 flex-1 space-y-1">
          <p className="text-[11px] font-bold uppercase tracking-wider opacity-80">
            Recommended Action
          </p>
          <div className="space-y-1 text-xs leading-relaxed font-medium">
            {displayRecs.map((rec, idx) => (
              <p key={idx}>{rec}</p>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
