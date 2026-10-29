import { apiClient, getApiBaseUrl } from './client'
import type { AnalysisReport } from '../../entities/report'

export const reportsApi = {
  /** Fetch structured JSON analysis report. */
  async getReportJson(analysisId: string): Promise<AnalysisReport> {
    const response = await apiClient.get<AnalysisReport>(`/reports/analysis/${analysisId}`, {
      params: { format: 'json' },
    })
    return response.data
  },

  /** URL to the printable/downloadable HTML layout report. */
  getReportHtmlUrl(analysisId: string): string {
    return `${getApiBaseUrl()}/reports/analysis/${analysisId}?format=html`
  },

  /** Trigger download of structured JSON report. */
  async downloadReportJson(analysisId: string): Promise<void> {
    const report = await this.getReportJson(analysisId)
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report_${analysisId}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  },

  /** Open print-ready HTML report in a new browser tab/window. */
  openReportHtml(analysisId: string): void {
    window.open(this.getReportHtmlUrl(analysisId), '_blank', 'noopener,noreferrer')
  },
}
