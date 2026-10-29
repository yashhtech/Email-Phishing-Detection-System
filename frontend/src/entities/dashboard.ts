import { z } from 'zod'

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export const LLMUsageMetricSchema = z.object({
  total_calls: z.number(),
  analyzed_calls: z.number(),
  skipped_calls: z.number(),
  average_latency_ms: z.number(),
  models_breakdown: z.record(z.number()),
})
export type LLMUsageMetric = z.infer<typeof LLMUsageMetricSchema>

export const DashboardMetricsSchema = z.object({
  total_emails_analyzed: z.number(),
  threats_detected: z.number(),
  high_risk_emails: z.number(),
  critical_threats: z.number(),
  phishing_count: z.number(),
  bec_count: z.number(),
  credential_theft_count: z.number(),
  malware_related_events: z.number(),
  average_risk_score: z.number(),
  analysis_success_rate: z.number(),
  llm_usage: LLMUsageMetricSchema,
  average_analysis_latency_ms: z.number(),
})
export type DashboardMetrics = z.infer<typeof DashboardMetricsSchema>

// ---------------------------------------------------------------------------
// Charts
// ---------------------------------------------------------------------------

export const ThreatTimelinePointSchema = z.object({
  date: z.string(),
  clean: z.number(),
  suspicious: z.number(),
  malicious: z.number(),
  total: z.number(),
})
export type ThreatTimelinePoint = z.infer<typeof ThreatTimelinePointSchema>

export const RiskDistributionBucketSchema = z.object({
  tier: z.string(),
  count: z.number(),
  color: z.string(),
})
export type RiskDistributionBucket = z.infer<typeof RiskDistributionBucketSchema>

export const AttackTypeItemSchema = z.object({
  attack_type: z.string(),
  count: z.number(),
  percentage: z.number(),
})
export type AttackTypeItem = z.infer<typeof AttackTypeItemSchema>

export const SeverityDistributionItemSchema = z.object({
  severity: z.string(),
  count: z.number(),
  color: z.string(),
})
export type SeverityDistributionItem = z.infer<typeof SeverityDistributionItemSchema>

export const LatencyDistributionBucketSchema = z.object({
  bucket: z.string(),
  count: z.number(),
})
export type LatencyDistributionBucket = z.infer<typeof LatencyDistributionBucketSchema>

export const DetectionTrendPointSchema = z.object({
  date: z.string(),
  detection_rate_pct: z.number(),
  volume: z.number(),
})
export type DetectionTrendPoint = z.infer<typeof DetectionTrendPointSchema>

export const RecentThreatItemSchema = z.object({
  analysis_id: z.string(),
  email_id: z.string(),
  subject: z.string(),
  from_address: z.string(),
  from_domain: z.string(),
  risk_score: z.number(),
  risk_level: z.string(),
  verdict: z.string(),
  attack_type: z.string(),
  category: z.string(),
  received_at: z.string(),
  has_attachments: z.boolean(),
})
export type RecentThreatItem = z.infer<typeof RecentThreatItemSchema>

export const DashboardChartsSchema = z.object({
  threats_over_time: z.array(ThreatTimelinePointSchema),
  risk_distribution: z.array(RiskDistributionBucketSchema),
  attack_type_distribution: z.array(AttackTypeItemSchema),
  severity_distribution: z.array(SeverityDistributionItemSchema),
  processing_time_distribution: z.array(LatencyDistributionBucketSchema),
  llm_usage: LLMUsageMetricSchema,
  detection_trends: z.array(DetectionTrendPointSchema),
  recent_threats: z.array(RecentThreatItemSchema),
})
export type DashboardCharts = z.infer<typeof DashboardChartsSchema>
