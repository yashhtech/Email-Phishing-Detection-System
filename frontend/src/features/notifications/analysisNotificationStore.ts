import { create } from 'zustand'

export type NormalizedVerdictTier = 'safe' | 'medium' | 'high'

export interface AnalysisNotificationData {
  analysis_id: string
  verdict: string
  severity?: string
  risk_score: number
  subject?: string | null
  sender?: string | null
  explanation?: string | null
  findings?: string[]
  security_checks?: {
    spf?: string
    dkim?: string
    dmarc?: string
    urls_analyzed?: number
    attachments_analyzed?: number
    [key: string]: unknown
  }
  threat_categories?: string[]
  recommendations?: string[]
  completed_at?: string | null
}

export interface ErrorNotificationData {
  id: string
  title: string
  message: string
  analysis_id?: string
}

export function classifyVerdictTier(
  severity?: string,
  riskScore: number = 0,
  verdict: string = ''
): NormalizedVerdictTier {
  const sev = (severity || '').toLowerCase()
  const verd = (verdict || '').toLowerCase()

  // Respect critical findings / severe overrides
  if (
    sev === 'critical' ||
    sev === 'high' ||
    verd === 'malicious' ||
    verd === 'block' ||
    verd === 'quarantine' ||
    riskScore >= 70
  ) {
    return 'high'
  }

  if (sev === 'medium' || verd === 'suspicious' || (riskScore >= 30 && riskScore < 70)) {
    return 'medium'
  }

  return 'safe'
}

export function getVerdictHeading(tier: NormalizedVerdictTier): string {
  switch (tier) {
    case 'safe':
      return 'Email Appears Safe'
    case 'medium':
      return 'Caution: Suspicious Email Detected'
    case 'high':
      return 'High Risk: Potential Phishing or Fraud'
  }
}

export function getDefaultRecommendation(tier: NormalizedVerdictTier): string {
  switch (tier) {
    case 'safe':
      return 'No major threat indicators were detected. Still verify unexpected requests before sharing sensitive information.'
    case 'medium':
      return 'Do not click links or open attachments until you independently verify the sender.'
    case 'high':
      return 'Do not click links, open attachments, reply, or share credentials or financial information. Report this email to your security team.'
  }
}

interface AnalysisNotificationStore {
  activeNotification: AnalysisNotificationData | null
  errorNotification: ErrorNotificationData | null
  notifiedIds: Set<string>
  notifyAnalysis: (data: AnalysisNotificationData) => void
  notifyError: (error: { title?: string; message: string; analysis_id?: string }) => void
  dismissNotification: () => void
  dismissError: () => void
  resetHistory: () => void
}

export const useAnalysisNotificationStore = create<AnalysisNotificationStore>((set, get) => ({
  activeNotification: null,
  errorNotification: null,
  notifiedIds: new Set<string>(),

  notifyAnalysis: (data: AnalysisNotificationData) => {
    if (!data.analysis_id) return
    const id = data.analysis_id.trim()
    const { notifiedIds } = get()

    // Prevent duplicate notifications for the same analysis ID
    if (notifiedIds.has(id)) {
      return
    }

    const updatedSet = new Set(notifiedIds)
    updatedSet.add(id)

    set({
      activeNotification: data,
      errorNotification: null,
      notifiedIds: updatedSet,
    })
  },

  notifyError: ({ title = 'Analysis Error', message, analysis_id }) => {
    set({
      errorNotification: {
        id: `err-${Date.now()}`,
        title,
        message,
        analysis_id,
      },
    })
  },

  dismissNotification: () => {
    set({ activeNotification: null })
  },

  dismissError: () => {
    set({ errorNotification: null })
  },

  resetHistory: () => {
    set({
      activeNotification: null,
      errorNotification: null,
      notifiedIds: new Set<string>(),
    })
  },
}))
