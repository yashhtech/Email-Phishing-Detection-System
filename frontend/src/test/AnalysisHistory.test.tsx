import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

// Mock the analysis API
vi.mock('../shared/api/analysis.api', () => ({
  analysisApi: {
    getHistory: vi.fn(),
  },
}))

// Mock AppShell to simplify DOM in unit tests
vi.mock('../shared/layout/AppShell', () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div data-testid="app-shell">{children}</div>,
}))

// Mock useNavigate
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

import { AnalysisHistoryPage } from '../pages/AnalysisHistoryPage'
import { analysisApi } from '../shared/api/analysis.api'

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
        <AnalysisHistoryPage />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const mockHistoryResponse = {
  items: [
    {
      analysis_id: 'analysis-uuid-1',
      email_id: 'email-uuid-1',
      timestamp: '2026-09-29T10:15:00Z',
      sender: 'ceo@phishing-lookalike.com',
      sender_domain: 'phishing-lookalike.com',
      subject: 'Urgent: Wire Transfer Approval Needed',
      classification: 'malicious',
      severity: 'critical',
      risk_score: 94,
      status: 'completed',
      attack_type: 'bec',
      duration_ms: 1250,
    },
    {
      analysis_id: 'analysis-uuid-2',
      email_id: 'email-uuid-2',
      timestamp: '2026-09-29T11:00:00Z',
      sender: 'newsletter@trusted-vendor.com',
      sender_domain: 'trusted-vendor.com',
      subject: 'Weekly Technology Roundup',
      classification: 'clean',
      severity: 'safe',
      risk_score: 8,
      status: 'completed',
      attack_type: 'none',
      duration_ms: 450,
    },
  ],
  total_count: 2,
  page: 1,
  page_size: 20,
  total_pages: 1,
  has_next: false,
  has_prev: false,
}

describe('AnalysisHistoryPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders all 7 required columns in table header', async () => {
    vi.mocked(analysisApi.getHistory).mockResolvedValue(mockHistoryResponse as any)
    renderComponent()

    expect(await screen.findByText('Timestamp')).toBeInTheDocument()
    expect(screen.getByText('Sender')).toBeInTheDocument()
    expect(screen.getByText('Subject')).toBeInTheDocument()
    expect(screen.getByText('Classification')).toBeInTheDocument()
    expect(screen.getByText('Severity')).toBeInTheDocument()
    expect(screen.getByText('Risk')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
  })

  it('renders data rows and navigates to complete analysis on click', async () => {
    vi.mocked(analysisApi.getHistory).mockResolvedValue(mockHistoryResponse as any)
    renderComponent()

    // Find row data
    const sender = await screen.findByText('ceo@phishing-lookalike.com')
    expect(sender).toBeInTheDocument()
    expect(screen.getByText('Urgent: Wire Transfer Approval Needed')).toBeInTheDocument()
    expect(screen.getByText('94')).toBeInTheDocument()

    // Click row
    fireEvent.click(sender.closest('tr')!)
    expect(mockNavigate).toHaveBeenCalledWith('/analysis/analysis-uuid-1')
  })

  it('renders empty state when no analysis records match', async () => {
    vi.mocked(analysisApi.getHistory).mockResolvedValue({
      items: [],
      total_count: 0,
      page: 1,
      page_size: 20,
      total_pages: 1,
      has_next: false,
      has_prev: false,
    } as any)
    renderComponent()

    const empty = await screen.findByText(/No matching analysis records found/i)
    expect(empty).toBeInTheDocument()
  })

  it('triggers search filter input and calls API with query', async () => {
    vi.mocked(analysisApi.getHistory).mockResolvedValue(mockHistoryResponse as any)
    renderComponent()

    const searchInput = screen.getByPlaceholderText(/Search by sender, domain, or subject/i)
    fireEvent.change(searchInput, { target: { value: 'ceo' } })

    expect(analysisApi.getHistory).toHaveBeenCalledWith(
      expect.objectContaining({
        search: 'ceo',
      })
    )
  })

  it('supports pagination controls', async () => {
    vi.mocked(analysisApi.getHistory).mockResolvedValue({
      ...mockHistoryResponse,
      total_count: 45,
      total_pages: 3,
      has_next: true,
    } as any)
    renderComponent()

    const pageIndicator = await screen.findByText('1 / 3')
    expect(pageIndicator).toBeInTheDocument()
    expect(screen.getByText(/Showing/i)).toBeInTheDocument()
  })
})
