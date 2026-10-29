// Primitive UI components — Button, Badge, Card, Skeleton, EmptyState, Alert
// These are LIGHT-THEME ONLY, no dark-mode variants

import { type ButtonHTMLAttributes, type FC, type ReactNode, forwardRef } from 'react'
import { cn } from '../lib/utils'

// ---------------------------------------------------------------------------
// Button
// ---------------------------------------------------------------------------

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline'
type ButtonSize = 'xs' | 'sm' | 'md' | 'lg'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  leftIcon?: ReactNode
  rightIcon?: ReactNode
}

const BUTTON_BASE =
  'inline-flex items-center justify-center gap-2 font-semibold transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]'

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'rounded-xl bg-violet-600 text-white shadow-violet-sm hover:bg-violet-700 hover:shadow-violet-md focus-visible:ring-violet-500',
  secondary:
    'rounded-xl border border-violet-200 bg-violet-50 text-violet-700 hover:bg-violet-100 focus-visible:ring-violet-400',
  ghost:
    'rounded-xl text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 focus-visible:ring-neutral-400',
  danger:
    'rounded-xl bg-danger-600 text-white shadow-sm hover:bg-danger-700 focus-visible:ring-danger-500',
  outline:
    'rounded-xl border border-neutral-200 bg-white text-neutral-700 shadow-xs hover:border-neutral-300 hover:bg-neutral-50 focus-visible:ring-neutral-400',
}

const BUTTON_SIZES: Record<ButtonSize, string> = {
  xs: 'h-7 px-2.5 text-2xs',
  sm: 'h-8 px-3.5 text-xs',
  md: 'h-9 px-4.5 text-sm',
  lg: 'h-11 px-6 text-base',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      loading = false,
      leftIcon,
      rightIcon,
      disabled,
      children,
      className,
      ...rest
    },
    ref,
  ) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      aria-busy={loading}
      className={cn(BUTTON_BASE, BUTTON_VARIANTS[variant], BUTTON_SIZES[size], className)}
      {...rest}
    >
      {loading ? (
        <ButtonSpinner />
      ) : (
        leftIcon && <span className="shrink-0">{leftIcon}</span>
      )}
      {children}
      {!loading && rightIcon && <span className="shrink-0">{rightIcon}</span>}
    </button>
  ),
)
Button.displayName = 'Button'

const ButtonSpinner: FC = () => (
  <svg
    className="h-4 w-4 animate-spin"
    xmlns="http://www.w3.org/2000/svg"
    fill="none"
    viewBox="0 0 24 24"
    aria-hidden="true"
  >
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path
      className="opacity-75"
      fill="currentColor"
      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
    />
  </svg>
)

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

type BadgeVariant =
  | 'default'
  | 'primary'
  | 'secondary'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'neutral'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'safe'
  | 'ai'
  | 'violet'
  | 'teal'
  | 'coral'
  | 'emerald'
  | 'amber'
  | 'ghost'

const BADGE_STYLES: Record<BadgeVariant, string> = {
  default: 'bg-neutral-100 text-neutral-700 border border-neutral-200/80',
  primary: 'bg-violet-50 text-violet-700 border border-violet-200/90 font-medium',
  secondary: 'bg-coral-50 text-coral-700 border border-coral-200/90 font-medium',
  success: 'bg-emerald-50 text-emerald-700 border border-emerald-200/90 font-medium',
  warning: 'bg-amber-50 text-amber-700 border border-amber-200/90 font-medium',
  danger: 'bg-rose-50 text-rose-700 border border-rose-200/90 font-medium',
  info: 'bg-sky-50 text-sky-700 border border-sky-200/90 font-medium',
  neutral: 'bg-slate-100/90 text-slate-600 border border-slate-200/80 font-medium',
  // Risk levels
  critical: 'bg-rose-50 text-rose-700 border border-rose-200/90 font-semibold',
  high: 'bg-orange-50 text-orange-700 border border-orange-200/90 font-semibold',
  medium: 'bg-amber-50 text-amber-700 border border-amber-200/90 font-semibold',
  low: 'bg-teal-50 text-teal-700 border border-teal-200/90 font-semibold',
  safe: 'bg-emerald-50 text-emerald-700 border border-emerald-200/90 font-semibold',
  // Special domain tags
  ai: 'bg-violet-50 text-violet-700 border border-violet-200/90 font-semibold shadow-xs',
  violet: 'bg-violet-50 text-violet-700 border border-violet-200/90 font-medium',
  teal: 'bg-teal-50 text-teal-700 border border-teal-200/90 font-medium',
  coral: 'bg-coral-50 text-coral-700 border border-coral-200/90 font-medium',
  emerald: 'bg-emerald-50 text-emerald-700 border border-emerald-200/90 font-medium',
  amber: 'bg-amber-50 text-amber-700 border border-amber-200/90 font-medium',
  ghost: 'bg-transparent text-neutral-600 border border-neutral-200',
}

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant
  children: ReactNode
  className?: string
  dot?: boolean
}

export const Badge: FC<BadgeProps> = ({ variant = 'default', children, className, dot, ...rest }) => (
  <span
    className={cn(
      'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold',
      BADGE_STYLES[variant],
      className,
    )}
    {...rest}
  >
    {dot && (
      <span
        className={cn(
          'h-1.5 w-1.5 rounded-full',
          variant === 'critical' || variant === 'danger'
            ? 'bg-danger-500'
            : variant === 'high' || variant === 'secondary'
              ? 'bg-coral-500'
              : variant === 'medium' || variant === 'warning'
                ? 'bg-warning-500'
                : variant === 'success' || variant === 'safe'
                  ? 'bg-success-500'
                  : variant === 'info'
                    ? 'bg-teal-500'
                    : 'bg-violet-500',
        )}
      />
    )}
    {children}
  </span>
)

// ---------------------------------------------------------------------------
// RiskBadge — severity-aware badge for risk levels
// ---------------------------------------------------------------------------

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe'

const RISK_LABELS: Record<RiskLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  safe: 'Safe',
}

interface RiskBadgeProps {
  level: RiskLevel
  className?: string
  showDot?: boolean
}

export const RiskBadge: FC<RiskBadgeProps> = ({ level, className, showDot = true }) => (
  <Badge
    variant={level}
    dot={showDot}
    className={cn('uppercase tracking-wide', className)}
    aria-label={`Risk level: ${RISK_LABELS[level]}`}
  >
    {RISK_LABELS[level]}
  </Badge>
)

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

interface CardProps {
  children: ReactNode
  className?: string
  padding?: 'none' | 'sm' | 'md' | 'lg'
}

const CARD_PADDING: Record<string, string> = {
  none: '',
  sm: 'p-4',
  md: 'p-5',
  lg: 'p-6',
}

export const Card: FC<CardProps> = ({ children, className, padding = 'md' }) => (
  <div
    className={cn(
      'rounded-2xl border border-neutral-150 bg-white shadow-sm',
      CARD_PADDING[padding],
      className,
    )}
  >
    {children}
  </div>
)

export const CardHeader: FC<{ children: ReactNode; className?: string }> = ({
  children,
  className,
}) => (
  <div
    className={cn(
      'flex items-center gap-3 border-b border-neutral-100 px-5 py-3.5 bg-neutral-50/50',
      className,
    )}
  >
    {children}
  </div>
)

export const CardTitle: FC<{ children: ReactNode; icon?: ReactNode; badge?: ReactNode }> = ({
  children,
  icon,
  badge,
}) => (
  <div className="flex w-full items-center gap-2">
    {icon && <span className="text-violet-500 shrink-0">{icon}</span>}
    <h3 className="text-sm font-semibold text-neutral-700">{children}</h3>
    {badge && <span className="ml-auto">{badge}</span>}
  </div>
)

export const CardBody: FC<{ children: ReactNode; className?: string }> = ({
  children,
  className,
}) => <div className={cn('p-5', className)}>{children}</div>

// ---------------------------------------------------------------------------
// Skeleton — animated loading placeholder
// ---------------------------------------------------------------------------

interface SkeletonProps {
  className?: string
  lines?: number
  height?: string
}

export const Skeleton: FC<SkeletonProps> = ({ className, lines = 1, height }) => {
  if (lines > 1) {
    return (
      <div className="space-y-2">
        {Array.from({ length: lines }).map((_, i) => (
          <SkeletonLine key={i} className={cn(i === lines - 1 && 'w-3/4', className)} />
        ))}
      </div>
    )
  }
  return <SkeletonLine className={className} height={height} />
}

const SkeletonLine: FC<{ className?: string; height?: string }> = ({ className, height }) => (
  <div
    className={cn('relative overflow-hidden rounded-lg bg-neutral-100', className)}
    style={{ height: height ?? '1rem' }}
    aria-hidden="true"
  >
    <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/60 to-transparent" />
  </div>
)

export const SkeletonCard: FC<{ rows?: number }> = ({ rows = 3 }) => (
  <Card>
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <Skeleton className="h-10 w-10 rounded-xl" />
        <div className="flex-1 space-y-1.5">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-3 w-1/2" />
        </div>
      </div>
      <Skeleton lines={rows} />
    </div>
  </Card>
)

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
  className?: string
}

export const EmptyState: FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className,
}) => (
  <div
    className={cn(
      'flex flex-col items-center justify-center gap-4 rounded-2xl border-2 border-dashed border-neutral-200 bg-neutral-50/50 py-16 text-center',
      className,
    )}
  >
    {icon && (
      <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-neutral-100 text-neutral-400">
        {icon}
      </span>
    )}
    <div className="space-y-1.5 max-w-xs">
      <h4 className="text-sm font-semibold text-neutral-700">{title}</h4>
      {description && <p className="text-xs text-neutral-400 leading-relaxed">{description}</p>}
    </div>
    {action && <div>{action}</div>}
  </div>
)

// ---------------------------------------------------------------------------
// Alert — info / success / warning / error
// ---------------------------------------------------------------------------

type AlertVariant = 'info' | 'success' | 'warning' | 'error'

const ALERT_STYLES: Record<
  AlertVariant,
  { container: string; border: string; icon: string; title: string; body: string }
> = {
  info: {
    container: 'bg-teal-50',
    border: 'border-teal-400',
    icon: 'text-teal-500',
    title: 'text-teal-900',
    body: 'text-teal-800',
  },
  success: {
    container: 'bg-success-50',
    border: 'border-success-400',
    icon: 'text-success-600',
    title: 'text-success-900',
    body: 'text-success-800',
  },
  warning: {
    container: 'bg-warning-50',
    border: 'border-warning-400',
    icon: 'text-warning-600',
    title: 'text-warning-900',
    body: 'text-warning-800',
  },
  error: {
    container: 'bg-danger-50',
    border: 'border-danger-400',
    icon: 'text-danger-600',
    title: 'text-danger-900',
    body: 'text-danger-800',
  },
}

interface AlertProps {
  variant?: AlertVariant
  title?: string
  children: ReactNode
  icon?: ReactNode
  className?: string
  onDismiss?: () => void
}

export const Alert: FC<AlertProps> = ({
  variant = 'info',
  title,
  children,
  icon,
  className,
  onDismiss,
}) => {
  const s = ALERT_STYLES[variant]
  return (
    <div
      role="alert"
      className={cn(
        'flex gap-3 rounded-xl border-l-4 p-4',
        s.container,
        s.border,
        className,
      )}
    >
      {icon && <span className={cn('mt-0.5 shrink-0', s.icon)}>{icon}</span>}
      <div className="flex-1 space-y-0.5 text-sm">
        {title && <p className={cn('font-semibold', s.title)}>{title}</p>}
        <div className={s.body}>{children}</div>
      </div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          className={cn('shrink-0 rounded p-0.5 hover:opacity-70 transition-opacity', s.icon)}
          aria-label="Dismiss"
        >
          <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// StatusDot
// ---------------------------------------------------------------------------

type StatusDotVariant = 'active' | 'idle' | 'error' | 'warning'

const STATUS_DOT_STYLES: Record<StatusDotVariant, string> = {
  active: 'bg-success-500',
  idle: 'bg-neutral-300',
  error: 'bg-danger-500',
  warning: 'bg-warning-500',
}

export const StatusDot: FC<{ status?: StatusDotVariant; pulse?: boolean; className?: string }> = ({
  status = 'active',
  pulse = false,
  className,
}) => (
  <span className={cn('relative flex h-2.5 w-2.5', className)}>
    {pulse && (
      <span
        className={cn(
          'absolute inline-flex h-full w-full animate-ping rounded-full opacity-50',
          STATUS_DOT_STYLES[status],
        )}
      />
    )}
    <span
      className={cn(
        'relative inline-flex h-2.5 w-2.5 rounded-full',
        STATUS_DOT_STYLES[status],
      )}
    />
  </span>
)

// ---------------------------------------------------------------------------
// Spinner (standalone)
// ---------------------------------------------------------------------------

export const Spinner: FC<{ size?: 'xs' | 'sm' | 'md' | 'lg'; className?: string }> = ({
  size = 'md',
  className,
}) => {
  const s =
    size === 'xs'
      ? 'h-3 w-3'
      : size === 'sm'
        ? 'h-4 w-4'
        : size === 'lg'
          ? 'h-8 w-8'
          : 'h-6 w-6'
  return (
    <svg
      className={cn('animate-spin text-violet-500', s, className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      role="status"
      aria-label="Loading"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Divider
// ---------------------------------------------------------------------------

export const Divider: FC<{ className?: string; label?: string }> = ({ className, label }) => {
  if (label) {
    return (
      <div className={cn('flex items-center gap-3', className)}>
        <div className="h-px flex-1 bg-neutral-200" />
        <span className="text-xs font-medium text-neutral-400">{label}</span>
        <div className="h-px flex-1 bg-neutral-200" />
      </div>
    )
  }
  return <div className={cn('h-px w-full bg-neutral-150', className)} />
}
