import { apiClient } from './client'
import type { EmailAnalysisResult } from '../../entities/emailAnalysis'

export interface StructuredEmailPayload {
  from_address: string
  to_addresses: string[]
  cc_addresses?: string[]
  reply_to?: string | null
  subject: string
  body_plain?: string | null
  body_html?: string | null
  raw_headers?: string | null
}

export const emailsApi = {
  async analyzeStructured(payload: StructuredEmailPayload): Promise<EmailAnalysisResult> {
    const response = await apiClient.post<EmailAnalysisResult>('/emails/analyze', payload)
    return response.data
  },

  async analyzeRaw(rawContent: string): Promise<EmailAnalysisResult> {
    const response = await apiClient.post<EmailAnalysisResult>('/emails/analyze/raw', {
      raw_content: rawContent,
    })
    return response.data
  },

  async uploadEml(emlFile: File, attachments?: File[]): Promise<EmailAnalysisResult> {
    const form = new FormData()
    form.append('eml_file', emlFile)
    if (attachments) {
      attachments.forEach((f) => form.append('attachments', f))
    }
    const response = await apiClient.post<EmailAnalysisResult>('/emails/analyze/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },

  async getById(emailId: string): Promise<EmailAnalysisResult> {
    const response = await apiClient.get<EmailAnalysisResult>(`/emails/${emailId}`)
    return response.data
  },
}
