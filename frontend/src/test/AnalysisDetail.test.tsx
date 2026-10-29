import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

// Mock the API module
vi.mock('../shared/api/analysis.api', () => ({
  analysisApi: {
    getById: vi.fn(),
  },
}))

// Mock AppShell to simplify DOM in unit tests
vi.mock('../shared/layout/AppShell', () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div data-testid="app-shell">{children}</div>,
}))

import { AnalysisDetailPage } from '../pages/AnalysisDetailPage'
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

function renderPage(id = 'test-analysis-123') {
  return render(
    <QueryClientProvider client={makeQC()}>
      <MemoryRouter initialEntries={[`/analysis/${id}`]}>
        <Routes>
          <Route path="/analysis/:id" element={<AnalysisDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const mockCompletedClean = {
  analysis_id: 'test-analysis-123',
  email_id: 'email-1',
  status: 'completed',
  raw_status: 'COMPLETE',
  verdict: 'clean',
  overall_risk_score: 12,
  risk_level: 'safe',
  started_at: '2026-09-29T10:00:00Z',
  completed_at: '2026-09-29T10:00:02Z',
  duration_ms: 1850,
  error_message: null,
  threat_signals: [],
  risk_score: {
    composite_score: 12,
    risk_level: 'safe',
    spf_subscore: 0,
    ml_subscore: 5,
    sender_reputation_subscore: 0,
    factor_breakdown: {
      spf_status: 'pass',
      dkim_status: 'pass',
      dmarc_status: 'pass',
    },
    scoring_version: '2026.1',
  },
  ml_prediction: {
    model_name: 'email-threat-ensemble',
    model_version: 'v1.4.0',
    classification: 'benign',
    phishing_probability: 0.05,
    spam_probability: 0.08,
    malware_probability: 0.01,
    confidence: 0.94,
  },
  llm_analysis: null,
  threat_intel_results: [],
}

const mockCompletedPhishing = {
  ...mockCompletedClean,
  verdict: 'malicious',
  overall_risk_score: 88,
  risk_level: 'critical',
  threat_signals: [
    {
      id: 'sig-1',
      signal_type: 'url_reputation',
      category: 'phishing',
      severity: 'critical',
      attack_type: 'credential_harvesting',
      confidence: 0.96,
      source: 'virustotal',
      title: 'Deceptive Credential Harvesting URL',
      description: 'The email body links to a credential harvesting site impersonating Microsoft 365.',
      indicator_value: 'https://login-microsoft-secure.attacker-domain.xyz/auth',
    },
    {
      id: 'sig-2',
      signal_type: 'semantic_intent',
      category: 'social_engineering',
      severity: 'high',
      attack_type: 'phishing',
      confidence: 0.89,
      source: 'groq',
      title: 'High Urgency Coercive Language',
      description: 'The email claims account suspension within 24 hours to induce panic.',
      indicator_value: null,
    },
  ],
  llm_analysis: {
    model_name: 'llama-3.3-70b-versatile',
    prompt_version: '2026.1',
    threat_narrative: 'This email employs classic credential harvesting tactics impersonating Microsoft 365.',
    executive_summary: 'Targeted phishing attack requesting immediate credential renewal under threat of account deactivation.',
    recommended_action: 'quarantine',
    reasoning: 'Intent: credential_harvesting. Impersonation: Microsoft 365. Credential request: True. Payment request: False.',
    extracted_iocs: [
      { type: 'social_engineering_tactic', value: 'urgency' },
      { type: 'social_engineering_tactic', value: 'authority' },
      { type: 'evidence_quote', value: 'Your account will be suspended within 24 hours' },
    ],
    safety_passed: true,
    confidence_score: 0.93,
    latency_ms: 640,
  },
  threat_intel_results: [
    {
      indicator_type: 'url',
      indicator_value: 'https://login-microsoft-secure.attacker-domain.xyz/auth',
      provider: 'virustotal',
      reputation: 'malicious',
      threat_score: 92,
      tags: ['phishing', 'credential-stealer'],
      last_checked_at: '2026-09-29T10:00:01Z',
    },
  ],
}

describe('AnalysisDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders loading skeleton while query is pending', () => {
    vi.mocked(analysisApi.getById).mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByTestId('app-shell')).toBeInTheDocument()
  })

  it('renders executive overview metrics correctly for clean email', async () => {
    vi.mocked(analysisApi.getById).mockResolvedValue(mockCompletedClean as any)
    renderPage()

    // Risk score
    const scores = await screen.findAllByText('12')
    expect(scores.length).toBeGreaterThan(0)

    // Verdict
    const cleanVerdicts = await screen.findAllByText(/clean/i)
    expect(cleanVerdicts.length).toBeGreaterThan(0)

    // Security signals (SPF, DKIM, DMARC)
    expect(screen.getByText('SPF')).toBeInTheDocument()
    expect(screen.getByText('DKIM')).toBeInTheDocument()
    expect(screen.getByText('DMARC')).toBeInTheDocument()

    // ML classification
    expect(screen.getByText(/email-threat-ensemble/i)).toBeInTheDocument()
    expect(screen.getByText(/v1.4.0/i)).toBeInTheDocument()

    // LLM skipped notice
    expect(screen.getByText(/Semantic analysis was not performed/i)).toBeInTheDocument()

    // Empty states
    expect(screen.getByText(/No threat intelligence results/i)).toBeInTheDocument()
    expect(screen.getByText(/No evidence collected/i)).toBeInTheDocument()
  })

  it('renders complete forensic dossier for phishing threat email', async () => {
    vi.mocked(analysisApi.getById).mockResolvedValue(mockCompletedPhishing as any)
    renderPage()

    // Overall Risk Score
    const scores = await screen.findAllByText('88')
    expect(scores.length).toBeGreaterThan(0)

    // 8 Deterministic Security Signals
    expect(screen.getByText('SPF')).toBeInTheDocument()
    expect(screen.getByText('DKIM')).toBeInTheDocument()
    expect(screen.getByText('DMARC')).toBeInTheDocument()
    expect(screen.getByText('Sender')).toBeInTheDocument()
    expect(screen.getByText('Reply-To')).toBeInTheDocument()
    expect(screen.getByText('Domain')).toBeInTheDocument()
    expect(screen.getByText('URL')).toBeInTheDocument()
    expect(screen.getByText('Attachment')).toBeInTheDocument()

    // ML Engine Classification
    expect(screen.getByText(/ML Engine Classification/i)).toBeInTheDocument()
    expect(screen.getByText('Phishing')).toBeInTheDocument()

    // Groq LLM Semantic Analysis
    expect(screen.getByText(/Groq LLM Semantic Analysis/i)).toBeInTheDocument()
    expect(screen.getByText(/llama-3.3-70b-versatile/i)).toBeInTheDocument()
    expect(screen.getAllByText(/urgency/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/authority/i)).toBeInTheDocument()
    expect(screen.getByText(/Your account will be suspended within 24 hours/i)).toBeInTheDocument()

    // Threat Intelligence Table
    expect(screen.getByText(/External Threat Intelligence/i)).toBeInTheDocument()
    expect(screen.getByText('virustotal')).toBeInTheDocument()
    expect(screen.getAllByText('malicious').length).toBeGreaterThanOrEqual(1)

    // Evidence Section with labeled fields
    expect(screen.getByText(/Forensic Evidence/i)).toBeInTheDocument()
    const detectedLabels = screen.getAllByText(/What was detected/i)
    expect(detectedLabels.length).toBe(2)
    const whyLabels = screen.getAllByText(/Why it matters/i)
    expect(whyLabels.length).toBe(2)
    expect(screen.getAllByText(/Deceptive Credential Harvesting URL/i).length).toBeGreaterThanOrEqual(1)

    // AI-inferred tag verification
    expect(screen.getByText(/AI-inferred — not independently verified/i)).toBeInTheDocument()
    // Verified technical signal tag verification
    expect(screen.getByText(/Verified Technical Signal/i)).toBeInTheDocument()
  })

  it('renders safety warning banner when safety_passed is false', async () => {
    const unsafeLLM = {
      ...mockCompletedPhishing,
      llm_analysis: {
        ...mockCompletedPhishing.llm_analysis,
        safety_passed: false,
      },
    }
    vi.mocked(analysisApi.getById).mockResolvedValue(unsafeLLM as any)
    renderPage()

    const warning = await screen.findByText(/Safety Gateway Warning/i)
    expect(warning).toBeInTheDocument()
  })

  it('renders processing state when analysis is queued or processing', async () => {
    const queuedData = {
      ...mockCompletedClean,
      status: 'processing',
    }
    vi.mocked(analysisApi.getById).mockResolvedValue(queuedData as any)
    renderPage()

    const processingMsg = await screen.findByText(/Threat analysis is in progress/i)
    expect(processingMsg).toBeInTheDocument()
  })
})
