import { apiClient } from './client'
import type { AnalysisDetail, AnalysisHistoryResponse } from '../../entities/emailAnalysis'

export interface AnalysisHistoryParams {
  page?: number
  page_size?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
  search?: string
  start_date?: string
  end_date?: string
  severity?: string
  attack_type?: string
  sender?: string
  min_risk?: number
  max_risk?: number
  status?: string
  classification?: string
}

export const analysisApi = {
  async getById(analysisId: string): Promise<AnalysisDetail> {
    const response = await apiClient.get<AnalysisDetail>(`/analysis/${analysisId}`)
    return response.data
  },

  async getHistory(params: AnalysisHistoryParams = {}): Promise<AnalysisHistoryResponse> {
    const cleanParams: Record<string, string | number> = {}
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '' && value !== 'all') {
        cleanParams[key] = value
      }
    }
    const response = await apiClient.get<AnalysisHistoryResponse>('/analysis/history', {
      params: cleanParams,
    })
    return response.data
  },
}
