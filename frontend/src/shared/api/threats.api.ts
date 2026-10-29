import { apiClient } from './client'

export interface ThreatSignalItem {
  id: string
  analysis_id: string
  signal_type: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  attack_type: string
  confidence: number
  source: string
  title: string
  description: string
  indicator_value: string | null
  created_at: string
}

export interface ThreatsListResponse {
  items: ThreatSignalItem[]
  total: number
  page: number
  page_size: number
  severity_counts: Record<string, number>
  attack_type_counts: Record<string, number>
}

export const threatsApi = {
  async list(params?: {
    severity?: string
    attack_type?: string
    page?: number
    page_size?: number
  }): Promise<ThreatsListResponse> {
    const response = await apiClient.get<ThreatsListResponse>('/threats', { params })
    return response.data
  },
}
