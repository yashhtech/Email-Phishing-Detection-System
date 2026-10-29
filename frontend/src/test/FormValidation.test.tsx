import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { EmailAnalyzerPage } from '../pages/EmailAnalyzerPage'
import { emailsApi } from '../shared/api/emails.api'

// Mock AppShell to simplify rendering
vi.mock('../shared/layout/AppShell', () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div data-testid="app-shell">{children}</div>,
}))

// Mock emailsApi
vi.mock('../shared/api/emails.api', () => ({
  emailsApi: {
    analyzeStructured: vi.fn(),
    analyzeRaw: vi.fn(),
    uploadEml: vi.fn(),
    getById: vi.fn(),
  },
}))

function renderEmailAnalyzer() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <EmailAnalyzerPage />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('Email Submission Form Validation', () => {
  it('renders Email Threat Analyzer title and input tabs', () => {
    renderEmailAnalyzer()
    expect(screen.getByText('Email Threat Analyzer')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /structured form/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /paste email/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /upload/i })).toBeInTheDocument()
  })

  it('shows required field errors when submitting an empty structured form', async () => {
    renderEmailAnalyzer()

    // The submit button is "Analyze Email"
    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/sender address \(from\) is required/i)).toBeInTheDocument()
      expect(screen.getByText(/at least one recipient \(to\) is required/i)).toBeInTheDocument()
      expect(screen.getByText(/subject line is required/i)).toBeInTheDocument()
      expect(screen.getByText(/email body is required/i)).toBeInTheDocument()
    })
  })

  it('shows invalid email format error for From field', async () => {
    renderEmailAnalyzer()

    // Get the From input by its label id
    const fromInput = screen.getByLabelText(/from \(sender\)/i)
    const toInput = screen.getByLabelText(/to \(recipient\)/i)
    const subjectInput = screen.getByLabelText(/subject/i)
    // Body textarea has empty label, use placeholder
    const bodyInput = screen.getByPlaceholderText(/paste plain text body here/i)

    fireEvent.change(fromInput, { target: { value: 'not-an-email' } })
    fireEvent.change(toInput, { target: { value: 'valid@test.com' } })
    fireEvent.change(subjectInput, { target: { value: 'Test Subject' } })
    fireEvent.change(bodyInput, { target: { value: 'Test email body content' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/please enter a valid email address/i)).toBeInTheDocument()
    })
  })

  it('shows invalid recipient format error for To field', async () => {
    renderEmailAnalyzer()

    const fromInput = screen.getByLabelText(/from \(sender\)/i)
    const toInput = screen.getByLabelText(/to \(recipient\)/i)
    const subjectInput = screen.getByLabelText(/subject/i)
    const bodyInput = screen.getByPlaceholderText(/paste plain text body here/i)

    fireEvent.change(fromInput, { target: { value: 'valid@sender.com' } })
    fireEvent.change(toInput, { target: { value: 'invalid-recipient' } })
    fireEvent.change(subjectInput, { target: { value: 'Test Subject' } })
    fireEvent.change(bodyInput, { target: { value: 'Test email body content' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/invalid recipient email format/i)).toBeInTheDocument()
    })
  })

  it('shows error when raw email is empty and submitting raw mode', async () => {
    renderEmailAnalyzer()

    // Switch to Paste Email tab
    const rawTab = screen.getByRole('tab', { name: /paste email/i })
    fireEvent.click(rawTab)

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/please paste the complete email message/i)).toBeInTheDocument()
    })
  })

  it('shows error when raw email is too short', async () => {
    renderEmailAnalyzer()

    const rawTab = screen.getByRole('tab', { name: /paste email/i })
    fireEvent.click(rawTab)

    // Find raw textarea - it has a placeholder starting with From:
    const rawTextarea = screen.getByPlaceholderText(/From:.*sender name/is)
    fireEvent.change(rawTextarea, { target: { value: 'Too short' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/pasted content is too short/i)).toBeInTheDocument()
    })
  })

  it('calls analyzeStructured when valid structured form is submitted', async () => {
    vi.mocked(emailsApi.analyzeStructured).mockResolvedValue({
      email_id: 'email-1',
      analysis_id: 'analysis-1',
      status: 'completed',
      verdict: 'clean',
      message_id: 'msg-1',
      from_address: 'test@sender.com',
      from_domain: 'sender.com',
      to_addresses: ['target@corp.com'],
      cc_addresses: [],
      reply_to: null,
      subject: 'Test Subject',
      received_at: new Date().toISOString(),
      body_preview: 'Short test body',
      body_plain: 'Short test body',
      body_html: null,
      headers: {
        message_id: 'msg-1',
        from_raw: 'test@sender.com',
        to_raw: ['target@corp.com'],
        cc_raw: [],
        reply_to: null,
        subject: 'Test Subject',
        date: new Date().toISOString(),
        spf_status: 'pass',
        spf_details: null,
        dkim_status: 'pass',
        dkim_details: null,
        dmarc_status: 'pass',
        dmarc_details: null,
        hop_count: 1,
        raw_headers: {},
      },
      urls: [],
      attachments: [],
      initial_risk_score: 5,
      initial_risk_level: 'safe',
      threat_signals: [],
    } as any)

    renderEmailAnalyzer()

    const fromInput = screen.getByLabelText(/from \(sender\)/i)
    const toInput = screen.getByLabelText(/to \(recipient\)/i)
    const subjectInput = screen.getByLabelText(/subject/i)
    const bodyInput = screen.getByPlaceholderText(/paste plain text body here/i)

    fireEvent.change(fromInput, { target: { value: 'test@sender.com' } })
    fireEvent.change(toInput, { target: { value: 'target@corp.com' } })
    fireEvent.change(subjectInput, { target: { value: 'Test Subject' } })
    fireEvent.change(bodyInput, { target: { value: 'This is a valid email body content' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(emailsApi.analyzeStructured).toHaveBeenCalledWith(
        expect.objectContaining({
          from_address: 'test@sender.com',
          to_addresses: ['target@corp.com'],
          subject: 'Test Subject',
        })
      )
    })
  })

  it('validates CC field email format', async () => {
    renderEmailAnalyzer()

    const fromInput = screen.getByLabelText(/from \(sender\)/i)
    const toInput = screen.getByLabelText(/to \(recipient\)/i)
    const ccInput = screen.getByLabelText(/cc \(carbon copy\)/i)
    const subjectInput = screen.getByLabelText(/subject/i)
    const bodyInput = screen.getByPlaceholderText(/paste plain text body here/i)

    fireEvent.change(fromInput, { target: { value: 'valid@sender.com' } })
    fireEvent.change(toInput, { target: { value: 'valid@recipient.com' } })
    fireEvent.change(ccInput, { target: { value: 'not-an-email' } })
    fireEvent.change(subjectInput, { target: { value: 'Test Subject' } })
    fireEvent.change(bodyInput, { target: { value: 'Valid email body content for testing' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/invalid cc email format/i)).toBeInTheDocument()
    })
  })

  it('validates Reply-To field email format', async () => {
    renderEmailAnalyzer()

    const fromInput = screen.getByLabelText(/from \(sender\)/i)
    const toInput = screen.getByLabelText(/to \(recipient\)/i)
    const replyToInput = screen.getByLabelText(/reply-to/i)
    const subjectInput = screen.getByLabelText(/subject/i)
    const bodyInput = screen.getByPlaceholderText(/paste plain text body here/i)

    fireEvent.change(fromInput, { target: { value: 'valid@sender.com' } })
    fireEvent.change(toInput, { target: { value: 'valid@recipient.com' } })
    fireEvent.change(replyToInput, { target: { value: 'bad-reply-to' } })
    fireEvent.change(subjectInput, { target: { value: 'Test Subject' } })
    fireEvent.change(bodyInput, { target: { value: 'Valid email body content for testing' } })

    const submitBtn = screen.getByRole('button', { name: /^analyze email$/i })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/please enter a valid reply-to email address/i)).toBeInTheDocument()
    })
  })
})
