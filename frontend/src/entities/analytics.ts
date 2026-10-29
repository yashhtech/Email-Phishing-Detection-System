import { z } from 'zod'

// ---------------------------------------------------------------------------
// Date Range & Meta
// ---------------------------------------------------------------------------

export const DateRangePresetSchema = z.enum(['24h', '7d', '30d', '90d'])
export type DateRangePreset = z.infer<typeof DateRangePresetSchema>

export const DateRangeMetaSchema = z.object({
  preset: z.string(),
  start_date: z.string(),
  end_date: z.string(),
  total_events: z.number().optional(),
})
export type DateRangeMeta = z.infer<typeof DateRangeMetaSchema>

// ---------------------------------------------------------------------------
// Trends & Distributions
// ---------------------------------------------------------------------------

export const ThreatTrendPointSchema = z.object({
  date: z.string(),
  threats: z.number(),
  clean: z.number(),
  total: z.number().optional(),
})
export type ThreatTrendPoint = z.infer<typeof ThreatTrendPointSchema>

export const AttackTypeTrendPointSchema = z.object({
  attack_type: z.string(),
  count: z.number(),
  percentage: z.number().optional(),
})
export type AttackTypeTrendPoint = z.infer<typeof AttackTypeTrendPointSchema>

export const RiskDistributionPointSchema = z.object({
  level: z.string(), // 'critical' | 'high' | 'medium' | 'low' | 'safe'
  count: z.number(),
  percentage: z.number().optional(),
  color: z.string().optional(),
})
export type RiskDistributionPoint = z.infer<typeof RiskDistributionPointSchema>

export const SenderDomainPointSchema = z.object({
  domain: z.string(),
  total: z.number(),
  threats: z.number(),
  threat_rate: z.number(),
})
export type SenderDomainPoint = z.infer<typeof SenderDomainPointSchema>

export const DetectionRatePointSchema = z.object({
  date: z.string(),
  detection_rate: z.number(),
  volume: z.number().optional(),
})
export type DetectionRatePoint = z.infer<typeof DetectionRatePointSchema>

// ---------------------------------------------------------------------------
// Model & Pipeline Metrics
// ---------------------------------------------------------------------------

export const FalsePositiveStatsSchema = z.object({
  data_available: z.boolean(),
  labeled_count: z.number().optional(),
  false_positives: z.number().optional(),
  false_negatives: z.number().optional(),
  false_positive_rate: z.number().optional(),
  precision: z.number().optional(),
  recall: z.number().optional(),
  accuracy: z.number().optional(),
})
export type FalsePositiveStats = z.infer<typeof FalsePositiveStatsSchema>

export const MLPerformanceMetricsSchema = z.object({
  total_predictions: z.number(),
  avg_confidence: z.number(),
  avg_latency_ms: z.number(),
  label_breakdown: z.record(z.number()),
  probabilities: z.record(z.number()).optional(),
})
export type MLPerformanceMetrics = z.infer<typeof MLPerformanceMetricsSchema>

export const LLMUtilizationMetricsSchema = z.object({
  utilization_rate: z.number(),
  total_invocations: z.number(),
  safety_failures: z.number(),
  avg_latency_ms: z.number(),
  avg_confidence: z.number().optional(),
  model_breakdown: z.record(z.number()),
})
export type LLMUtilizationMetrics = z.infer<typeof LLMUtilizationMetricsSchema>

export const ProcessingLatencyStatsSchema = z.object({
  avg_ms: z.number(),
  min_ms: z.number(),
  max_ms: z.number(),
  p50_ms: z.number(),
  p90_ms: z.number(),
  p99_ms: z.number(),
})
export type ProcessingLatencyStats = z.infer<typeof ProcessingLatencyStatsSchema>

export const ThreatIntelUsageStatsSchema = z.object({
  total_queries: z.number().optional(),
  verdicts_breakdown: z.record(z.number()),
  queries_by_provider: z.record(z.number()),
  indicator_types: z.record(z.number()),
})
export type ThreatIntelUsageStats = z.infer<typeof ThreatIntelUsageStatsSchema>

// ---------------------------------------------------------------------------
// Combined Overview & Query Params
// ---------------------------------------------------------------------------

export const AnalyticsOverviewSchema = z.object({
  meta: DateRangeMetaSchema,
  threat_trends: z.array(ThreatTrendPointSchema),
  detection_rates: z.array(DetectionRatePointSchema),
  attack_types: z.array(AttackTypeTrendPointSchema),
  risk_distribution: z.array(RiskDistributionPointSchema),
  top_sender_domains: z.array(SenderDomainPointSchema),
  ml_performance: MLPerformanceMetricsSchema,
  llm_utilization: LLMUtilizationMetricsSchema,
  processing_latency: ProcessingLatencyStatsSchema,
  threat_intel: ThreatIntelUsageStatsSchema,
  false_positives: FalsePositiveStatsSchema,
})
export type AnalyticsOverview = z.infer<typeof AnalyticsOverviewSchema>

export interface AnalyticsParams {
  preset?: '24h' | '7d' | '30d' | '90d' | string
  start_date?: string
  end_date?: string
}
