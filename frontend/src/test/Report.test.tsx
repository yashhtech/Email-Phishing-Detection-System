import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

// Mock the API client
vi.mock('../shared/api/reports.api', () => ({
  reportsApi: {
    getReportJson: vi.fn(),
    getReportHtmlUrl: vi.fn((id: string) => `/api/v1/reports/analysis/${id}?format=html`),
    downloadReportJson: vi.fn(),
    openReportHtml: vi.fn(),
  },
}))

// Mock AppShell to render children
vi.mock('../shared/layout/AppShell', () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div data-testid="app-shell">{children}</div>,
}))

import { ReportViewPage } from '../pages/ReportViewPage'
import { reportsApi } from '../shared/api/reports.api'
import type { AnalysisReport } from '../entities/report'

function makeQC() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderReportPage(id = 'test-analysis-id') {
  return render(
    <QueryClientProvider client={makeQC()}>
      <MemoryRouter initialEntries={[`/analysis/${id}/report`]}>
        <Routes>
          <Route path="/analysis/:id/report" element={<ReportViewPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const mockReport: AnalysisReport = {
  report_id: 'report-uuid-1234',
  analysis_id: 'test-analysis-id',
  org_id: 'org-uuid-5678',
  org_name: 'Acme Security Corp',
  engine_version: '1.0.0',
  scoring_version: '1.0',
  classification: {
    verdict: 'malicious',
    status: 'completed',
    primary_attack_type: 'credential_harvesting',
    severity: 'critical',
    confidence: 0.98,
  },
  risk_score: {
    overall_risk_score: 94,
    risk_level: 'critical',
    composite_score: 94,
    scoring_version: '1.0',
    spf_subscore: 10,
    dkim_subscore: 10,
    dmarc_subscore: 15,
    ml_subscore: 25,
    url_subscore: 20,
    attachment_subscore: 0,
    sender_reputation_subscore: 14,
    factor_breakdown: null,
  },
  email_metadata: {
    email_id: 'email-uuid-999',
    message_id: '<phish-999@evil.net>',
    from_address: 'support@billing-evil.com',
    from_domain: 'billing-evil.com',
    to_addresses: ['cfo@acme.com'],
    cc_addresses: [],
    reply_to: null,
    subject: 'Urgent Wire Transfer Authorization Needed',
    received_at: '2026-09-30T08:00:00Z',
    has_attachments: false,
    attachment_count: 0,
    url_count: 1,
    spf_status: 'fail',
    dkim_status: 'none',
    dmarc_status: 'fail',
    return_path: 'bounce@billing-evil.com',
  },
  security_signals: [],
  ml_analysis: {
    model_name: 'xgboost-ensemble',
    model_version: 'v2.1',
    classification: 'phishing',
    confidence: 0.97,
    phishing_probability: 0.96,
    spam_probability: 0.03,
    malware_probability: 0.01,
    latency_ms: 85,
  },
  groq_analysis: {
    model_name: 'llama-3.3-70b-versatile',
    prompt_version: 'v1.0',
    threat_narrative: 'Message masquerades as executive finance alert with coercive payment instructions.',
    executive_summary: 'Severe credential and financial fraud attempt identified.',
    recommended_action: 'quarantine',
    reasoning: 'Impersonates accounting team, lacks cryptographic signatures, host on malicious registrar.',
    extracted_iocs: [{ type: 'url', value: 'http://billing-evil.com/login' }],
    safety_passed: true,
    confidence_score: 0.95,
    latency_ms: 720,
  },
  threat_intelligence: [
    {
      indicator_type: 'domain',
      indicator_value: 'billing-evil.com',
      provider: 'virustotal',
      reputation: 'malicious',
      threat_score: 88,
      tags: ['phishing', 'fast-flux'],
      last_checked_at: '2026-09-30T08:00:00Z',
    },
  ],
  evidence: [
    {
      title: 'DMARC Verification Failure',
      severity: 'critical',
      source: 'dmarc_analyzer',
      category: 'authentication',
      attack_type: 'spoofing',
      description: 'Domain alignment check failed with policy=quarantine.',
      indicator_value: 'billing-evil.com',
      confidence: 1.0,
      why_it_matters: 'Email sender authentication checks failed. Attackers forge headers to impersonate executives.',
    },
  ],
  timestamps: {
    email_received_at: '2026-09-30T08:00:00Z',
    analysis_started_at: '2026-09-30T08:00:01Z',
    analysis_completed_at: '2026-09-30T08:00:03Z',
    report_generated_at: '2026-09-30T08:05:00Z',
    duration_ms: 2000,
  },
  generated_by: 'lead.analyst@acme.com',
  confidentiality: 'CONFIDENTIAL - RESTRICTED SECURITY INCIDENT REPORT',
}

describe('ReportViewPage', () => {
  it('renders report loading state initially', () => {
    vi.mocked(reportsApi.getReportJson).mockReturnValue(new Promise(() => {}))
    renderReportPage()
    expect(screen.getByTestId('app-shell')).toBeInTheDocument()
  })

  it('renders error alert when report query fails', async () => {
    vi.mocked(reportsApi.getReportJson).mockRejectedValue(new Error('Network error loading report'))
    renderReportPage()
    const errorAlert = await screen.findByText(/Failed to Load Report/i)
    expect(errorAlert).toBeInTheDocument()
  })

  it('renders report header, verdict, risk score, and tenant', async () => {
    vi.mocked(reportsApi.getReportJson).mockResolvedValue(mockReport)
    renderReportPage()

    // Title and metadata
    expect(await screen.findByText('Email Security Incident Report')).toBeInTheDocument()
    expect(screen.getByText(/Acme Security Corp/i)).toBeInTheDocument()
    expect(screen.getByText(/Engine v1.0.0/i)).toBeInTheDocument()

    // Verdict and Risk Score
    expect(screen.getByText('94')).toBeInTheDocument()
    expect(screen.getByText(/Verdict: malicious/i)).toBeInTheDocument()
    expect(screen.getByText(/critical Risk/i)).toBeInTheDocument()
  })

  it('renders email metadata, evidence findings, and why it matters', async () => {
    vi.mocked(reportsApi.getReportJson).mockResolvedValue(mockReport)
    renderReportPage()

    // Email metadata
    expect(await screen.findByText('support@billing-evil.com')).toBeInTheDocument()
    expect(screen.getByText('Urgent Wire Transfer Authorization Needed')).toBeInTheDocument()
    expect(screen.getByText(/SPF: fail/i)).toBeInTheDocument()

    // Evidence
    expect(screen.getByText('DMARC Verification Failure')).toBeInTheDocument()
    expect(screen.getByText(/Why it matters:/i)).toBeInTheDocument()
  })

  it('renders ML model and Groq AI analysis sections', async () => {
    vi.mocked(reportsApi.getReportJson).mockResolvedValue(mockReport)
    renderReportPage()

    // ML
    expect(await screen.findByText('xgboost-ensemble')).toBeInTheDocument()

    // Groq
    expect(screen.getByText(/AI • llama-3.3-70b-versatile/i)).toBeInTheDocument()
    expect(screen.getByText('Severe credential and financial fraud attempt identified.')).toBeInTheDocument()
    expect(screen.getByText('Recommended Action:')).toBeInTheDocument()
    expect(screen.getAllByText(/quarantine/i).length).toBeGreaterThanOrEqual(1)
  })

  it('renders threat intelligence feed table and audit footer', async () => {
    vi.mocked(reportsApi.getReportJson).mockResolvedValue(mockReport)
    renderReportPage()

    // Threat intelligence
    expect(await screen.findByText('virustotal')).toBeInTheDocument()
    expect(screen.getByText('billing-evil.com')).toBeInTheDocument()

    // Audit footer
    expect(screen.getByText(/lead.analyst@acme.com/i)).toBeInTheDocument()
  })

  it('renders action buttons for print and export', async () => {
    vi.mocked(reportsApi.getReportJson).mockResolvedValue(mockReport)
    renderReportPage()

    expect(await screen.findByRole('button', { name: /Print \/ Save PDF/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Export JSON/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Open HTML/i })).toBeInTheDocument()
  })
})
