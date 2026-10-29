import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { AnalyticsOverview } from '../entities/analytics'

// Mock AppShell to simplify DOM in unit tests
vi.mock('../shared/layout/AppShell', () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="app-shell">{children}</div>
  ),
}))

// Mock Recharts ResponsiveContainer to avoid 0x0 size issues in jsdom
vi.mock('recharts', async () => {
  const actual = await vi.importActual('recharts')
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
      <div style={{ width: 500, height: 300 }}>{children}</div>
    ),
  }
})

// Mock the analytics API
vi.mock('../shared/api/analytics.api', () => ({
  analyticsApi: {
    getOverview: vi.fn(),
    getExportUrl: vi.fn(({ preset }: { preset?: string } = {}) =>
      `/api/v1/analytics/export?preset=${preset || '7d'}`,
    ),
  },
}))

import { AnalyticsPage } from '../pages/AnalyticsPage'
import { analyticsApi } from '../shared/api/analytics.api'

function makeQC() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
}

function renderComponent() {
  return render(
    <QueryClientProvider client={makeQC()}>
      <MemoryRouter>
        <AnalyticsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const mockOverviewWithNoFeedback: AnalyticsOverview = {
  meta: {
    preset: '7d',
    start_date: '2026-09-23T00:00:00Z',
    end_date: '2026-09-30T00:00:00Z',
    total_events: 15420,
  },
  threat_trends: [
    { date: '2026-09-24', threats: 12, clean: 450, total: 462 },
    { date: '2026-09-25', threats: 28, clean: 510, total: 538 },
  ],
  detection_rates: [
    { date: '2026-09-24', detection_rate: 98.4, volume: 462 },
    { date: '2026-09-25', detection_rate: 99.1, volume: 538 },
  ],
  attack_types: [
    { attack_type: 'Phishing', count: 180, percentage: 45.0 },
    { attack_type: 'BEC', count: 120, percentage: 30.0 },
    { attack_type: 'Malware', count: 60, percentage: 15.0 },
  ],
  risk_distribution: [
    { level: 'Critical', count: 45, percentage: 15.0, color: '#ef4444' },
    { level: 'High', count: 85, percentage: 28.3, color: '#f97316' },
    { level: 'Medium', count: 120, percentage: 40.0, color: '#f59e0b' },
    { level: 'Safe', count: 50, percentage: 16.7, color: '#22c55e' },
  ],
  top_sender_domains: [
    { domain: 'suspicious-billing.com', total: 140, threats: 120, threat_rate: 85.7 },
    { domain: 'external-vendor-update.net', total: 95, threats: 40, threat_rate: 42.1 },
    { domain: 'trusted-partner.com', total: 1250, threats: 5, threat_rate: 0.4 },
  ],
  ml_performance: {
    total_predictions: 15420,
    avg_confidence: 0.965,
    avg_latency_ms: 12.4,
    label_breakdown: {
      phishing: 400,
      clean: 14800,
      suspicious: 220,
    },
    probabilities: {
      '0.0-0.2': 14800,
      '0.8-1.0': 400,
    },
  },
  llm_utilization: {
    utilization_rate: 28.5,
    total_invocations: 4390,
    safety_failures: 2,
    avg_latency_ms: 642.0,
    avg_confidence: 0.942,
    model_breakdown: {
      'llama-3.3-70b-versatile': 3890,
      'gpt-4o-mini': 500,
    },
  },
  processing_latency: {
    avg_ms: 45.2,
    min_ms: 8.5,
    max_ms: 310.0,
    p50_ms: 32.1,
    p90_ms: 88.4,
    p99_ms: 195.0,
  },
  threat_intel: {
    total_queries: 8200,
    verdicts_breakdown: {
      malicious: 380,
      suspicious: 190,
      clean: 7630,
    },
    queries_by_provider: {
      VirusTotal: 4100,
      AbuseIPDB: 2800,
    },
    indicator_types: {
      url: 4900,
      domain: 2100,
    },
  },
  false_positives: {
    data_available: false,
  },
}

describe('AnalyticsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders page heading', async () => {
    vi.mocked(analyticsApi.getOverview).mockResolvedValueOnce(mockOverviewWithNoFeedback)
    renderComponent()

    expect(await screen.findByRole('heading', { name: /Security Analytics/i })).toBeInTheDocument()
    expect(screen.getByText('Live Telemetry')).toBeInTheDocument()
  })

  it('renders date range selector with 4 presets and updates selection', async () => {
    vi.mocked(analyticsApi.getOverview).mockResolvedValue(mockOverviewWithNoFeedback)
    renderComponent()

    const btn24h = await screen.findByRole('button', { name: '24h' })
    const btn7d = screen.getByRole('button', { name: '7d' })
    const btn30d = screen.getByRole('button', { name: '30d' })
    const btn90d = screen.getByRole('button', { name: '90d' })

    expect(btn24h).toBeInTheDocument()
    expect(btn7d).toBeInTheDocument()
    expect(btn30d).toBeInTheDocument()
    expect(btn90d).toBeInTheDocument()

    // Default 7d is selected
    expect(btn7d).toHaveAttribute('aria-pressed', 'true')

    // Click 30d
    fireEvent.click(btn30d)
    expect(btn30d).toHaveAttribute('aria-pressed', 'true')
    expect(btn7d).toHaveAttribute('aria-pressed', 'false')

    await waitFor(() => {
      expect(analyticsApi.getOverview).toHaveBeenCalledWith({ preset: '30d' })
    })
  })

  it('renders Export CSV link with appropriate href', async () => {
    vi.mocked(analyticsApi.getOverview).mockResolvedValue(mockOverviewWithNoFeedback)
    renderComponent()

    const exportLink = await screen.findByRole('link', { name: /Export CSV/i })
    expect(exportLink).toBeInTheDocument()
    expect(exportLink).toHaveAttribute('href', expect.stringContaining('/api/v1/analytics/export?preset=7d'))

    // When preset changes, export link URL updates
    const btn90d = screen.getByRole('button', { name: '90d' })
    fireEvent.click(btn90d)

    expect(exportLink).toHaveAttribute('href', expect.stringContaining('/api/v1/analytics/export?preset=90d'))
  })

  it('renders all section titles', async () => {
    vi.mocked(analyticsApi.getOverview).mockResolvedValueOnce(mockOverviewWithNoFeedback)
    renderComponent()

    // Wait for data load
    await screen.findByRole('heading', { name: /Security Analytics/i })

    expect(screen.getByText('Threat Trends')).toBeInTheDocument()
    expect(screen.getByText('Detection Rate')).toBeInTheDocument()
    expect(screen.getByText('Attack Type Distribution')).toBeInTheDocument()
    expect(screen.getByText('Risk Distribution')).toBeInTheDocument()
    expect(screen.getByText('Top Sender Domains')).toBeInTheDocument()
    expect(screen.getByText('ML Performance')).toBeInTheDocument()
    expect(screen.getByText('LLM Utilization')).toBeInTheDocument()
    expect(screen.getByText('Processing Latency')).toBeInTheDocument()
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument()
    expect(screen.getByText('False Positive Tracking')).toBeInTheDocument()
  })

  it('renders false positive tracking empty state when data_available: false', async () => {
    vi.mocked(analyticsApi.getOverview).mockResolvedValueOnce(mockOverviewWithNoFeedback)
    renderComponent()

    expect(await screen.findByText('No labeled feedback data')).toBeInTheDocument()
    expect(
      screen.getByText(/Ground truth labels have not been submitted yet/i),
    ).toBeInTheDocument()
  })

  it('renders false positive tracking metrics when data_available: true', async () => {
    const mockWithFeedback: AnalyticsOverview = {
      ...mockOverviewWithNoFeedback,
      false_positives: {
        data_available: true,
        labeled_count: 520,
        false_positives: 12,
        false_negatives: 3,
        false_positive_rate: 2.3,
        precision: 97.7,
        recall: 99.4,
        accuracy: 97.1,
      },
    }

    vi.mocked(analyticsApi.getOverview).mockResolvedValueOnce(mockWithFeedback)
    renderComponent()

    expect(await screen.findByText('Labeled Data Count')).toBeInTheDocument()
    expect(screen.getByText('520')).toBeInTheDocument()
    expect(screen.getByText('False Positives (FPs)')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('False Negatives (FNs)')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('FP Rate')).toBeInTheDocument()
    expect(screen.getByText('2.3%')).toBeInTheDocument()
  })
})
