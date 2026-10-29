import { apiClient } from './client'
import type {
  DashboardCharts,
  DashboardMetrics,
  RecentThreatItem,
} from '../../entities/dashboard'

export const dashboardApi = {
  /**
   * Fetch all 12 key production metrics aggregated from PostgreSQL.
   */
  async getMetrics(): Promise<DashboardMetrics> {
    const response = await apiClient.get<DashboardMetrics>('/dashboard/metrics')
    return response.data
  },

  /**
   * Fetch all 8 chart datasets.
   * @param days Window in days for time-series charts (default 14).
   */
  async getCharts(days: number = 14): Promise<DashboardCharts> {
    const response = await apiClient.get<DashboardCharts>(`/dashboard/charts?days=${days}`)
    return response.data
  },

  /**
   * Fetch recent threat detections for table inspection.
   * @param limit Number of incidents to return (default 20).
   */
  async getRecentThreats(limit: number = 20): Promise<RecentThreatItem[]> {
    const response = await apiClient.get<RecentThreatItem[]>(`/dashboard/recent-threats?limit=${limit}`)
    return response.data
  },
}
