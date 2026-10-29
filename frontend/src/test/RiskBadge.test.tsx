import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { RiskBadge } from '@/shared/ui/RiskBadge'

describe('RiskBadge', () => {
  it('renders the correct label for critical', () => {
    render(<RiskBadge level="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('renders the correct aria-label', () => {
    render(<RiskBadge level="high" />)
    expect(screen.getByLabelText('Risk level: High')).toBeInTheDocument()
  })

  it('renders safe badge', () => {
    render(<RiskBadge level="safe" />)
    expect(screen.getByText('Safe')).toBeInTheDocument()
  })
})
