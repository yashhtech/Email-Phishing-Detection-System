import { useCallback, useMemo, useState } from 'react'
import type { EmailAnalysisResult } from '../../entities/emailAnalysis'
import { emailsApi } from '../../shared/api/emails.api'
import { useAnalysisNotificationStore } from '../notifications'

export type InputMode = 'structured' | 'raw' | 'upload'
export type AnalysisStatus = 'idle' | 'validating' | 'uploading' | 'analyzing' | 'completed' | 'failed'

export interface StructuredFormData {
  from: string
  to: string
  cc: string
  replyTo: string
  subject: string
  body: string
  bodyType: 'plain' | 'html'
  headers: string
}

export interface AttachmentItem {
  id: string
  file: File
  name: string
  size: number
  type: string
  isExecutable: boolean
  isArchive: boolean
}

export interface DetectedUrl {
  url: string
  domain: string
  protocol: string
  isIp: boolean
  defanged: string
}

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
const URL_REGEX = /(https?:\/\/[^\s<>"{}|\\^`]+)/gi
const IP_REGEX = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/

const EXECUTABLE_EXTS = new Set([
  '.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jse', '.wsf', '.msi', '.dll', '.ps1', '.hta',
])
const ARCHIVE_EXTS = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.iso'])

export const MAX_BODY_CHARS = 250_000 // ~250 KB
export const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024 // 10 MB per file
export const MAX_TOTAL_ATTACHMENT_SIZE = 25 * 1024 * 1024 // 25 MB total

export function useEmailAnalyzer() {
  const [mode, setMode] = useState<InputMode>('structured')
  const [status, setStatus] = useState<AnalysisStatus>('idle')
  const [error, setError] = useState<string | null>(null)
  const [uploadProgress, setUploadProgress] = useState<number>(0)
  const [result, setResult] = useState<EmailAnalysisResult | null>(null)

  // Structured form state
  const [structuredData, setStructuredData] = useState<StructuredFormData>({
    from: '',
    to: '',
    cc: '',
    replyTo: '',
    subject: '',
    body: '',
    bodyType: 'plain',
    headers: '',
  })
  const [formErrors, setFormErrors] = useState<Record<string, string>>({})

  // Raw pasted state
  const [rawEmail, setRawEmail] = useState<string>('')
  const [rawError, setRawError] = useState<string | null>(null)

  // File upload state (.eml)
  const [emlFile, setEmlFile] = useState<File | null>(null)
  const [uploadAttachments, setUploadAttachments] = useState<AttachmentItem[]>([])
  const [uploadError, setUploadError] = useState<string | null>(null)

  // -------------------------------------------------------------------------
  // Live URL Extraction from active text
  // -------------------------------------------------------------------------
  const liveUrls = useMemo<DetectedUrl[]>(() => {
    const textToScan = mode === 'structured' ? structuredData.body : rawEmail
    if (!textToScan || textToScan.length < 5) return []

    const matches = textToScan.match(URL_REGEX)
    if (!matches) return []

    const unique = Array.from(new Set(matches))
    return unique.map((u) => {
      const clean = u.replace(/[.,;!?>]+$/, '')
      let domain = ''
      let protocol = 'http:'
      let isIp = false

      try {
        const parsed = new URL(clean)
        domain = parsed.hostname
        protocol = parsed.protocol
        isIp = IP_REGEX.test(domain)
      } catch {
        domain = clean.split('/')[2] || clean
      }

      const defanged = clean
        .replace(/^https?:\/\//i, (p) => (p.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'))
        .replace(/\./g, '[.]')

      return {
        url: clean,
        domain,
        protocol,
        isIp,
        defanged,
      }
    })
  }, [mode, structuredData.body, rawEmail])

  // -------------------------------------------------------------------------
  // Live Header Extraction preview for raw or structured
  // -------------------------------------------------------------------------
  const liveHeaders = useMemo<Record<string, string>>(() => {
    const textToScan = mode === 'structured' ? structuredData.headers : rawEmail
    if (!textToScan) return {}

    const headers: Record<string, string> = {}
    const lines = textToScan.split('\n')
    let currentKey = ''

    for (const line of lines) {
      if (mode === 'raw' && line.trim() === '') {
        // Headers end at first blank line in raw RFC 822
        break
      }
      const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (match) {
        currentKey = match[1]
        headers[currentKey] = match[2].trim()
      } else if (currentKey && (line.startsWith(' ') || line.startsWith('\t'))) {
        headers[currentKey] += ' ' + line.trim()
      }
    }
    return headers
  }, [mode, structuredData.headers, rawEmail])

  // -------------------------------------------------------------------------
  // Attachment Handlers
  // -------------------------------------------------------------------------
  const addAttachment = useCallback((files: FileList | File[]) => {
    const newItems: AttachmentItem[] = []
    let currentTotal = uploadAttachments.reduce((acc, f) => acc + f.size, 0)

    for (const f of Array.from(files)) {
      if (f.size > MAX_ATTACHMENT_SIZE) {
        setUploadError(`File "${f.name}" exceeds the maximum 10 MB limit (${(f.size / 1024 / 1024).toFixed(1)} MB).`)
        return
      }
      if (currentTotal + f.size > MAX_TOTAL_ATTACHMENT_SIZE) {
        setUploadError('Total attachments exceed the 25 MB limit.')
        return
      }
      currentTotal += f.size

      const ext = '.' + (f.name.split('.').pop()?.toLowerCase() || '')
      newItems.push({
        id: `${f.name}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        file: f,
        name: f.name,
        size: f.size,
        type: f.type || 'application/octet-stream',
        isExecutable: EXECUTABLE_EXTS.has(ext),
        isArchive: ARCHIVE_EXTS.has(ext),
      })
    }

    setUploadError(null)
    setUploadAttachments((prev) => [...prev, ...newItems])
  }, [uploadAttachments])

  const removeAttachment = useCallback((id: string) => {
    setUploadAttachments((prev) => prev.filter((item) => item.id !== id))
  }, [])

  // -------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------
  const validateStructuredForm = useCallback((): boolean => {
    const errors: Record<string, string> = {}

    if (!structuredData.from.trim()) {
      errors.from = 'Sender address (From) is required.'
    } else if (!EMAIL_REGEX.test(structuredData.from.trim())) {
      errors.from = 'Please enter a valid email address (e.g., user@domain.com).'
    }

    if (!structuredData.to.trim()) {
      errors.to = 'At least one recipient (To) is required.'
    } else {
      const toList = structuredData.to.split(/[,;\n]+/).map((e) => e.trim()).filter(Boolean)
      const invalid = toList.find((e) => !EMAIL_REGEX.test(e))
      if (invalid) {
        errors.to = `Invalid recipient email format: "${invalid}"`
      }
    }

    if (structuredData.cc.trim()) {
      const ccList = structuredData.cc.split(/[,;\n]+/).map((e) => e.trim()).filter(Boolean)
      const invalid = ccList.find((e) => !EMAIL_REGEX.test(e))
      if (invalid) {
        errors.cc = `Invalid CC email format: "${invalid}"`
      }
    }

    if (structuredData.replyTo.trim() && !EMAIL_REGEX.test(structuredData.replyTo.trim())) {
      errors.replyTo = 'Please enter a valid Reply-To email address.'
    }

    if (!structuredData.subject.trim()) {
      errors.subject = 'Subject line is required.'
    }

    if (!structuredData.body.trim()) {
      errors.body = 'Email body is required.'
    } else if (structuredData.body.length > MAX_BODY_CHARS) {
      errors.body = `Body exceeds the maximum limit of ${MAX_BODY_CHARS.toLocaleString()} characters.`
    }

    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }, [structuredData])

  const validateRaw = useCallback((): boolean => {
    if (!rawEmail.trim()) {
      setRawError('Please paste the complete email message or headers/body.')
      return false
    }
    if (rawEmail.length < 15) {
      setRawError('Pasted content is too short to be a valid email.')
      return false
    }
    setRawError(null)
    return true
  }, [rawEmail])

  const validateUpload = useCallback((): boolean => {
    if (!emlFile) {
      setUploadError('Please select or drop an .eml file to analyze.')
      return false
    }
    if (!emlFile.name.toLowerCase().endsWith('.eml') && !emlFile.name.toLowerCase().endsWith('.msg') && !emlFile.name.toLowerCase().endsWith('.txt')) {
      setUploadError('Only .eml, .msg, or .txt raw email files are supported.')
      return false
    }
    setUploadError(null)
    return true
  }, [emlFile])

  // -------------------------------------------------------------------------
  // Main Analyze Action
  // -------------------------------------------------------------------------
  const analyzeEmail = useCallback(async () => {
    setError(null)
    setResult(null)
    setStatus('validating')

    if (mode === 'structured') {
      if (!validateStructuredForm()) {
        setStatus('idle')
        return
      }
      setStatus('analyzing')
      try {
        const toAddresses = structuredData.to.split(/[,;\n]+/).map((e) => e.trim()).filter(Boolean)
        const ccAddresses = structuredData.cc.split(/[,;\n]+/).map((e) => e.trim()).filter(Boolean)

        const payload = {
          from_address: structuredData.from.trim(),
          to_addresses: toAddresses,
          cc_addresses: ccAddresses,
          reply_to: structuredData.replyTo.trim() || null,
          subject: structuredData.subject.trim(),
          body_plain: structuredData.bodyType === 'plain' ? structuredData.body : null,
          body_html: structuredData.bodyType === 'html' ? structuredData.body : null,
          raw_headers: structuredData.headers.trim() || null,
        }

        const data = await emailsApi.analyzeStructured(payload)
        setResult(data)
        setStatus('completed')
        useAnalysisNotificationStore.getState().notifyAnalysis({
          analysis_id: data.analysis_id,
          verdict: data.verdict,
          severity: data.severity || data.initial_risk_level,
          risk_score: data.risk_score ?? data.initial_risk_score ?? 0,
          subject: data.subject,
          sender: data.from_address,
          explanation: data.explanation,
          findings: data.findings || data.threat_signals || [],
          security_checks: data.security_checks,
          threat_categories: data.threat_categories,
          recommendations: data.recommendations,
          completed_at: data.completed_at ? String(data.completed_at) : null,
        })
      } catch (err: unknown) {
        setStatus('failed')
        const message = err instanceof Error ? err.message : 'Analysis failed. Please check backend status.'
        setError(message)
        useAnalysisNotificationStore.getState().notifyError({
          title: 'Analysis Failed',
          message,
        })
      }
    } else if (mode === 'raw') {
      if (!validateRaw()) {
        setStatus('idle')
        return
      }
      setStatus('analyzing')
      try {
        const data = await emailsApi.analyzeRaw(rawEmail)
        setResult(data)
        setStatus('completed')
        useAnalysisNotificationStore.getState().notifyAnalysis({
          analysis_id: data.analysis_id,
          verdict: data.verdict,
          severity: data.severity || data.initial_risk_level,
          risk_score: data.risk_score ?? data.initial_risk_score ?? 0,
          subject: data.subject,
          sender: data.from_address,
          explanation: data.explanation,
          findings: data.findings || data.threat_signals || [],
          security_checks: data.security_checks,
          threat_categories: data.threat_categories,
          recommendations: data.recommendations,
          completed_at: data.completed_at ? String(data.completed_at) : null,
        })
      } catch (err: unknown) {
        setStatus('failed')
        const message = err instanceof Error ? err.message : 'Analysis failed. Please check backend status.'
        setError(message)
        useAnalysisNotificationStore.getState().notifyError({
          title: 'Analysis Failed',
          message,
        })
      }
    } else if (mode === 'upload') {
      if (!validateUpload()) {
        setStatus('idle')
        return
      }
      setStatus('uploading')
      setUploadProgress(25)

      try {
        setUploadProgress(50)
        const filesToSend = uploadAttachments.map((a) => a.file)
        const data = await emailsApi.uploadEml(emlFile!, filesToSend)
        setUploadProgress(100)
        setResult(data)
        setStatus('completed')
        useAnalysisNotificationStore.getState().notifyAnalysis({
          analysis_id: data.analysis_id,
          verdict: data.verdict,
          severity: data.severity || data.initial_risk_level,
          risk_score: data.risk_score ?? data.initial_risk_score ?? 0,
          subject: data.subject,
          sender: data.from_address,
          explanation: data.explanation,
          findings: data.findings || data.threat_signals || [],
          security_checks: data.security_checks,
          threat_categories: data.threat_categories,
          recommendations: data.recommendations,
          completed_at: data.completed_at ? String(data.completed_at) : null,
        })
      } catch (err: unknown) {
        setStatus('failed')
        const message = err instanceof Error ? err.message : 'Upload failed. Please check backend status.'
        setError(message)
        useAnalysisNotificationStore.getState().notifyError({
          title: 'Upload Failed',
          message,
        })
      }
    }
  }, [mode, structuredData, rawEmail, emlFile, uploadAttachments, validateStructuredForm, validateRaw, validateUpload])

  const resetAnalysis = useCallback(() => {
    setStatus('idle')
    setResult(null)
    setError(null)
    setUploadProgress(0)
  }, [])

  return {
    mode,
    setMode,
    status,
    error,
    uploadProgress,
    result,
    // Structured
    structuredData,
    setStructuredData,
    formErrors,
    // Raw
    rawEmail,
    setRawEmail,
    rawError,
    // Upload
    emlFile,
    setEmlFile,
    uploadAttachments,
    addAttachment,
    removeAttachment,
    uploadError,
    // Live previews
    liveUrls,
    liveHeaders,
    // Actions
    analyzeEmail,
    resetAnalysis,
  }
}
