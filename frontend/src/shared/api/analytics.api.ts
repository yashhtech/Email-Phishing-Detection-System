import { apiClient, getApiBaseUrl } from './client'
import type { AnalyticsOverview, AnalyticsParams } from '../../entities/analytics'

export const analyticsApi = {
  /**
   * Fetch complete analytics overview across threat intelligence,
   * ML/LLM models, processing latency, trends, and risk distribution.
   */
  async getOverview(params?: AnalyticsParams): Promise<AnalyticsOverview> {
    const response = await apiClient.get<any>('/analytics/overview', {
      params,
    })
    const raw = response.data

    // If backend returns snake_case / differing key names, normalize them cleanly
    const meta = {
      preset: raw.date_range?.preset || raw.meta?.preset || params?.preset || '7d',
      start_date:
        raw.date_range?.start || raw.meta?.start_date || new Date().toISOString(),
      end_date:
        raw.date_range?.end || raw.meta?.end_date || new Date().toISOString(),
      total_events: raw.meta?.total_events,
    }

    const threat_trends = (raw.threat_trends || []).map((t: any) => ({
      date: t.date || (t.timestamp ? new Date(t.timestamp).toLocaleDateString() : ''),
      threats: t.threats ?? (t.suspicious || 0) + (t.malicious || 0) + (t.quarantine || 0) + (t.block || 0),
      clean: t.clean ?? 0,
      total: t.total ?? 0,
    }))

    const detection_rates = (raw.detection_rate || raw.detection_rates || []).map((d: any) => ({
      date: d.date || (d.timestamp ? new Date(d.timestamp).toLocaleDateString() : ''),
      detection_rate: d.detection_rate ?? 0,
      volume: d.volume ?? d.total_analyzed ?? 0,
    }))

    const attack_types = (raw.attack_type_trends || raw.attack_types || []).map((a: any) => ({
      attack_type: (a.attack_type || '').replace(/_/g, ' '),
      count: a.count ?? 0,
      percentage: a.percentage ?? 0,
    }))

    const risk_distribution = (raw.risk_distribution || []).map((r: any) => ({
      level: r.level || r.tier || '',
      count: r.count ?? 0,
      percentage: r.percentage ?? 0,
      color: r.color,
    }))

    const top_sender_domains = (raw.sender_domains || raw.top_sender_domains || []).map((s: any) => ({
      domain: s.domain || '',
      total: s.total ?? s.total_emails ?? 0,
      threats: s.threats ?? s.threat_count ?? 0,
      threat_rate: s.threat_rate ?? 0,
    }))

    const ml_raw = raw.ml_performance || {}
    const ml_performance = {
      total_predictions: ml_raw.total_predictions ?? 0,
      avg_confidence: ml_raw.avg_confidence ?? 0,
      avg_latency_ms: ml_raw.avg_latency_ms ?? 0,
      label_breakdown: ml_raw.label_breakdown || {
        phishing: ml_raw.phishing_detected ?? 0,
        clean: ml_raw.clean_detected ?? 0,
        spam: ml_raw.spam_detected ?? 0,
        malware: ml_raw.malware_detected ?? 0,
      },
      probabilities: ml_raw.probabilities,
    }

    const llm_raw = raw.llm_utilization || {}
    const llm_utilization = {
      utilization_rate: llm_raw.utilization_rate ?? (llm_raw.total_calls > 0 ? 100 : 0),
      total_invocations: llm_raw.total_invocations ?? llm_raw.total_calls ?? 0,
      safety_failures: llm_raw.safety_failures ?? 0,
      avg_latency_ms: llm_raw.avg_latency_ms ?? 0,
      avg_confidence: llm_raw.avg_confidence,
      model_breakdown: llm_raw.model_breakdown || llm_raw.models_breakdown || {},
    }

    const latency_raw = raw.processing_latency || {}
    const processing_latency = {
      avg_ms: latency_raw.avg_ms ?? 0,
      min_ms: latency_raw.min_ms ?? 0,
      max_ms: latency_raw.max_ms ?? 0,
      p50_ms: latency_raw.p50_ms ?? 0,
      p90_ms: latency_raw.p90_ms ?? 0,
      p99_ms: latency_raw.p99_ms ?? 0,
    }

    const ti_raw = raw.threat_intel || raw.threat_intel_usage || {}
    const threat_intel = {
      total_queries: ti_raw.total_queries ?? 0,
      verdicts_breakdown: ti_raw.verdicts_breakdown || {
        clean: ti_raw.clean_hits ?? 0,
        suspicious: ti_raw.suspicious_hits ?? 0,
        malicious: ti_raw.malicious_hits ?? 0,
        unknown: ti_raw.unknown_hits ?? 0,
      },
      queries_by_provider: ti_raw.queries_by_provider || ti_raw.providers_breakdown || {},
      indicator_types: ti_raw.indicator_types || {},
    }

    const fp_raw = raw.false_positives || raw.false_positive_stats || {}
    const false_positives = {
      data_available: fp_raw.data_available ?? (fp_raw.reported_count !== undefined && fp_raw.reported_count > 0),
      labeled_count: fp_raw.labeled_count ?? fp_raw.reported_count,
      false_positives: fp_raw.false_positives ?? fp_raw.confirmed_false_positive,
      false_negatives: fp_raw.false_negatives,
      false_positive_rate: fp_raw.false_positive_rate,
      precision: fp_raw.precision,
      recall: fp_raw.recall,
      accuracy: fp_raw.accuracy,
    }

    return {
      meta,
      threat_trends,
      detection_rates,
      attack_types,
      risk_distribution,
      top_sender_domains,
      ml_performance,
      llm_utilization,
      processing_latency,
      threat_intel,
      false_positives,
    }
  },

  /**
   * Get the direct CSV export URL for the specified analytics parameters.
   */
  getExportUrl(params?: AnalyticsParams): string {
    const base = `${getApiBaseUrl()}/analytics/export`
    if (!params) return base
    const searchParams = new URLSearchParams()
    if (params.preset) searchParams.set('preset', params.preset)
    if (params.start_date) searchParams.set('start_date', params.start_date)
    if (params.end_date) searchParams.set('end_date', params.end_date)
    const qs = searchParams.toString()
    return qs ? `${base}?${qs}` : base
  },
}
