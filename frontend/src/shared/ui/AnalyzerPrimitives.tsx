// Shared UI primitives for the Email Analyzer feature

import { type FC, type HTMLAttributes, type ReactNode, forwardRef } from 'react'
import { cn } from '../lib/utils'

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

type BadgeVariant = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'pass' | 'fail' | 'none'

const BADGE_CLASSES: Record<BadgeVariant, string> = {
  clean: 'bg-green-50 text-green-700 ring-1 ring-green-200',
  suspicious: 'bg-amber-50 text-amber-700 ring-1 ring-amber-200',
  malicious: 'bg-red-50 text-red-700 ring-1 ring-red-200',
  unknown: 'bg-gray-50 text-gray-500 ring-1 ring-gray-200',
  pass: 'bg-green-50 text-green-700 ring-1 ring-green-200',
  fail: 'bg-red-50 text-red-700 ring-1 ring-red-200',
  none: 'bg-gray-50 text-gray-400 ring-1 ring-gray-200',
}

export const StatusBadge: FC<{ variant: BadgeVariant; label: string; className?: string }> = ({
  variant,
  label,
  className,
}) => (
  <span
    className={cn(
      'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
      BADGE_CLASSES[variant],
      className,
    )}
  >
    {label}
  </span>
)

// ---------------------------------------------------------------------------
// RiskMeter
// ---------------------------------------------------------------------------

export const RiskMeter: FC<{ score: number; level: string }> = ({ score, level }) => {
  const clamp = Math.min(100, Math.max(0, score))
  const color =
    level === 'critical'
      ? 'bg-red-500'
      : level === 'high'
        ? 'bg-orange-500'
        : level === 'medium'
          ? 'bg-amber-400'
          : level === 'low'
            ? 'bg-violet-400'
            : 'bg-green-500'
  const textColor =
    level === 'critical'
      ? 'text-red-600'
      : level === 'high'
        ? 'text-orange-600'
        : level === 'medium'
          ? 'text-amber-600'
          : level === 'low'
            ? 'text-violet-600'
            : 'text-green-600'

  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Risk Score</span>
        <span className={cn('text-2xl font-bold tabular-nums', textColor)}>{Math.round(clamp)}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100">
        <div
          className={cn('h-full rounded-full transition-all duration-700', color)}
          style={{ width: `${clamp}%` }}
          role="progressbar"
          aria-valuenow={clamp}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      <p className={cn('text-xs font-semibold uppercase tracking-widest text-right', textColor)}>
        {level}
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// SectionCard
// ---------------------------------------------------------------------------

export const SectionCard: FC<{
  title: string
  icon?: ReactNode
  children: ReactNode
  className?: string
  badge?: ReactNode
}> = ({ title, icon, children, className, badge }) => (
  <section className={cn('card overflow-hidden', className)}>
    <header className="flex items-center gap-2 border-b border-gray-100 px-5 py-3.5 bg-gray-50/60">
      {icon && <span className="text-violet-600">{icon}</span>}
      <h3 className="text-sm font-semibold text-gray-700">{title}</h3>
      {badge && <span className="ml-auto">{badge}</span>}
    </header>
    <div className="p-5">{children}</div>
  </section>
)

// ---------------------------------------------------------------------------
// FieldRow — key/value row
// ---------------------------------------------------------------------------

export const FieldRow: FC<{ label: string; value?: ReactNode; mono?: boolean }> = ({
  label,
  value,
  mono,
}) => (
  <div className="flex flex-col gap-0.5 sm:flex-row sm:gap-4">
    <dt className="w-36 shrink-0 text-xs font-medium text-gray-400 uppercase tracking-wide pt-0.5">
      {label}
    </dt>
    <dd
      className={cn(
        'text-sm text-gray-800 break-all',
        mono && 'font-mono text-xs bg-gray-50 rounded px-2 py-1',
      )}
    >
      {value ?? <span className="text-gray-300">—</span>}
    </dd>
  </div>
)

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

export const Spinner: FC<{ size?: 'sm' | 'md' | 'lg'; className?: string }> = ({
  size = 'md',
  className,
}) => {
  const s = size === 'sm' ? 'h-4 w-4' : size === 'lg' ? 'h-8 w-8' : 'h-6 w-6'
  return (
    <svg
      className={cn('animate-spin text-violet-500', s, className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-label="Loading"
      role="status"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// TextInput
// ---------------------------------------------------------------------------

interface TextInputProps extends Omit<HTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string
  id: string
  error?: string
  hint?: string
  required?: boolean
  value: string
  onChange: (v: string) => void
  type?: string
  placeholder?: string
  maxLength?: number
  disabled?: boolean
}

export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(
  (
    { label, id, error, hint, required, value, onChange, type = 'text', placeholder, maxLength, disabled, className, ...rest },
    ref,
  ) => (
    <div className={cn('space-y-1', className)}>
      <label htmlFor={id} className="form-label">
        {label}
        {required && <span className="ml-1 text-red-500" aria-hidden="true">*</span>}
      </label>
      <input
        ref={ref}
        id={id}
        type={type}
        value={value}
        maxLength={maxLength}
        disabled={disabled}
        placeholder={placeholder}
        aria-required={required}
        aria-invalid={!!error}
        aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        className={cn('form-input', error && 'border-red-300 ring-red-100 focus:border-red-400')}
        onChange={(e) => onChange(e.target.value)}
        {...rest}
      />
      {maxLength && (
        <p className="text-right text-xs text-gray-400 tabular-nums">
          {value.length}/{maxLength}
        </p>
      )}
      {hint && !error && (
        <p id={`${id}-hint`} className="text-xs text-gray-400">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} role="alert" className="field-error">
          <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          {error}
        </p>
      )}
    </div>
  ),
)
TextInput.displayName = 'TextInput'

// ---------------------------------------------------------------------------
// Textarea
// ---------------------------------------------------------------------------

interface TextareaProps extends Omit<HTMLAttributes<HTMLTextAreaElement>, 'onChange'> {
  label: string
  id: string
  error?: string
  hint?: string
  required?: boolean
  value: string
  onChange: (v: string) => void
  rows?: number
  placeholder?: string
  maxLength?: number
  disabled?: boolean
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, id, error, hint, required, value, onChange, rows = 6, placeholder, maxLength, disabled, className, ...rest }, ref) => (
    <div className={cn('space-y-1', className)}>
      <label htmlFor={id} className="form-label">
        {label}
        {required && <span className="ml-1 text-red-500" aria-hidden="true">*</span>}
      </label>
      <textarea
        ref={ref}
        id={id}
        rows={rows}
        value={value}
        maxLength={maxLength}
        disabled={disabled}
        placeholder={placeholder}
        aria-required={required}
        aria-invalid={!!error}
        aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        className={cn('form-textarea', error && 'border-red-300 focus:border-red-400')}
        onChange={(e) => onChange(e.target.value)}
        {...rest}
      />
      <div className="flex items-center justify-between">
        {hint && !error && (
          <p id={`${id}-hint`} className="text-xs text-gray-400">{hint}</p>
        )}
        {maxLength && (
          <p className="ml-auto text-right text-xs text-gray-400 tabular-nums">
            {value.length.toLocaleString()}/{maxLength.toLocaleString()}
          </p>
        )}
      </div>
      {error && (
        <p id={`${id}-error`} role="alert" className="field-error">
          <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          {error}
        </p>
      )}
    </div>
  ),
)
Textarea.displayName = 'Textarea'
