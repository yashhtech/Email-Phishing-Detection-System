import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  AttackTypeDistributionChart,
  DetectionTrendsChart,
  LLMUsageTelemetryCard,
  ProcessingTimeChart,
  RecentThreatsTable,
  RiskDistributionChart,
  SeverityDistributionChart,
  ThreatsOverTimeChart,
} from '../features/dashboard/DashboardCharts'

describe('Dashboard Charts — Zero Records & Empty States', () => {
  it('renders graceful empty state when threats over time is empty', () => {
    render(<ThreatsOverTimeChart data={[]} loading={false} />)
    expect(screen.getByText('No threat timeline data')).toBeInTheDocument()
    expect(
      screen.getByText('Process emails to view daily threat patterns.'),
    ).toBeInTheDocument()
  })

  it('renders graceful empty state when risk distribution has zero counts', () => {
    render(
      <RiskDistributionChart
        data={[
          { tier: 'Safe (0-19)', count: 0, color: '#22c55e' },
          { tier: 'Low (20-39)', count: 0, color: '#8b5cf6' },
        ]}
        loading={false}
      />,
    )
    expect(screen.getByText('No risk distribution data')).toBeInTheDocument()
  })

  it('renders graceful empty state when attack types is empty', () => {
    render(<AttackTypeDistributionChart data={[]} loading={false} />)
    expect(screen.getByText('No attack signals identified')).toBeInTheDocument()
  })

  it('renders graceful empty state when severity distribution has zero counts', () => {
    render(
      <SeverityDistributionChart
        data={[
          { severity: 'Critical', count: 0, color: '#dc2626' },
          { severity: 'High', count: 0, color: '#f97316' },
        ]}
        loading={false}
      />,
    )
    expect(screen.getByText('No severity telemetry')).toBeInTheDocument()
  })

  it('renders graceful empty state when processing time is empty', () => {
    render(<ProcessingTimeChart data={[]} loading={false} />)
    expect(screen.getByText('No latency data recorded')).toBeInTheDocument()
  })

  it('renders graceful empty state when detection trends has zero volume', () => {
    render(<DetectionTrendsChart data={[]} loading={false} />)
    expect(screen.getByText('No trend data')).toBeInTheDocument()
  })

  it('renders graceful empty state when recent threats is empty', () => {
    render(<RecentThreatsTable threats={[]} loading={false} />)
    expect(screen.getByText('No recent threat detections')).toBeInTheDocument()
  })

  it('renders LLM usage telemetry with real computed values', () => {
    render(
      <LLMUsageTelemetryCard
        data={{
          total_calls: 120,
          analyzed_calls: 40,
          skipped_calls: 80,
          average_latency_ms: 615.4,
          models_breakdown: { 'llama-3.3-70b-versatile': 40 },
        }}
        loading={false}
      />,
    )
    expect(screen.getByText('Total Invocations')).toBeInTheDocument()
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.getByText('40')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
    expect(screen.getByText('615.4 ms')).toBeInTheDocument()
    expect(screen.getByText('llama-3.3-70b-versatile')).toBeInTheDocument()
  })
})
