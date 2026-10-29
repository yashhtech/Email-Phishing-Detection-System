import { z } from 'zod'

export const ExtractedURLSchema = z.object({
  url: z.string(),
  domain: z.string(),
  scheme: z.string(),
  path: z.string(),
  is_ip_address: z.boolean(),
  defanged_url: z.string(),
  reputation: z.enum(['clean', 'suspicious', 'malicious', 'unknown']),
  is_suspicious_tld: z.boolean(),
})
export type ExtractedURL = z.infer<typeof ExtractedURLSchema>

export const ExtractedAttachmentSchema = z.object({
  filename: z.string(),
  content_type: z.string(),
  size_bytes: z.number(),
  sha256: z.string(),
  is_executable: z.boolean(),
  is_archive: z.boolean(),
})
export type ExtractedAttachment = z.infer<typeof ExtractedAttachmentSchema>

export const ExtractedHeadersSchema = z.object({
  message_id: z.string(),
  from_raw: z.string(),
  to_raw: z.array(z.string()),
  cc_raw: z.array(z.string()),
  reply_to: z.string().nullable(),
  subject: z.string().nullable(),
  date: z.string(),
  spf_status: z.string(),
  spf_details: z.string().nullable(),
  dkim_status: z.string(),
  dkim_details: z.string().nullable(),
  dmarc_status: z.string(),
  dmarc_details: z.string().nullable(),
  hop_count: z.number(),
  raw_headers: z.record(z.string()),
})
export type ExtractedHeaders = z.infer<typeof ExtractedHeadersSchema>

export const EmailAnalysisResultSchema = z.object({
  email_id: z.string(),
  analysis_id: z.string(),
  status: z.string(),
  verdict: z.enum(['clean', 'suspicious', 'malicious', 'unknown']),
  message_id: z.string(),
  from_address: z.string(),
  from_domain: z.string(),
  to_addresses: z.array(z.string()),
  cc_addresses: z.array(z.string()),
  reply_to: z.string().nullable(),
  subject: z.string().nullable(),
  received_at: z.string(),
  body_preview: z.string().nullable(),
  body_plain: z.string().nullable(),
  body_html: z.string().nullable(),
  headers: ExtractedHeadersSchema,
  urls: z.array(ExtractedURLSchema),
  attachments: z.array(ExtractedAttachmentSchema),
  initial_risk_score: z.number().min(0).max(100),
  initial_risk_level: z.enum(['critical', 'high', 'medium', 'low', 'safe']),
  threat_signals: z.array(z.string()),
})
export type EmailAnalysisResult = z.infer<typeof EmailAnalysisResultSchema>

// ── Analysis Detail types (for GET /analysis/{id}) ──────────────────────────

export const ThreatSignalSchema = z.object({
  id: z.string(),
  signal_type: z.string(),
  category: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  attack_type: z.string(),
  confidence: z.number().min(0).max(1),
  source: z.string(),
  title: z.string(),
  description: z.string(),
  indicator_value: z.string().nullable(),
})
export type ThreatSignal = z.infer<typeof ThreatSignalSchema>

export const RiskScoreDetailSchema = z.object({
  composite_score: z.number(),
  risk_level: z.string(),
  spf_subscore: z.number().nullable(),
  ml_subscore: z.number().nullable(),
  sender_reputation_subscore: z.number().nullable(),
  factor_breakdown: z.record(z.unknown()).nullable(),
  scoring_version: z.string(),
})
export type RiskScoreDetail = z.infer<typeof RiskScoreDetailSchema>

export const MLPredictionSchema = z.object({
  model_name: z.string(),
  model_version: z.string(),
  classification: z.string(),
  phishing_probability: z.number(),
  spam_probability: z.number(),
  malware_probability: z.number(),
  confidence: z.number(),
})
export type MLPrediction = z.infer<typeof MLPredictionSchema>

export const LLMAnalysisSchema = z.object({
  model_name: z.string(),
  prompt_version: z.string(),
  threat_narrative: z.string(),
  executive_summary: z.string().nullable(),
  recommended_action: z.string(),
  reasoning: z.string().nullable(),
  extracted_iocs: z.array(z.record(z.unknown())),
  safety_passed: z.boolean(),
  confidence_score: z.number(),
  latency_ms: z.number().nullable(),
})
export type LLMAnalysis = z.infer<typeof LLMAnalysisSchema>

export const ThreatIntelResultSchema = z.object({
  indicator_type: z.string(),
  indicator_value: z.string(),
  provider: z.string(),
  reputation: z.string(),
  threat_score: z.number().nullable(),
  tags: z.array(z.string()),
  last_checked_at: z.string(),
})
export type ThreatIntelResult = z.infer<typeof ThreatIntelResultSchema>

export const AnalysisDetailSchema = z.object({
  analysis_id: z.string(),
  email_id: z.string(),
  status: z.enum(['queued', 'processing', 'completed', 'failed', 'unknown']),
  raw_status: z.string(),
  verdict: z.string(),
  overall_risk_score: z.number(),
  risk_level: z.string(),
  started_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  duration_ms: z.number().nullable(),
  error_message: z.string().nullable(),
  threat_signals: z.array(ThreatSignalSchema),
  risk_score: RiskScoreDetailSchema.nullable(),
  ml_prediction: MLPredictionSchema.nullable(),
  llm_analysis: LLMAnalysisSchema.nullable(),
  threat_intel_results: z.array(ThreatIntelResultSchema),
})
export type AnalysisDetail = z.infer<typeof AnalysisDetailSchema>

// ── Analysis History types (for GET /analysis/history) ──────────────────────

export const AnalysisHistoryItemSchema = z.object({
  analysis_id: z.string(),
  email_id: z.string(),
  timestamp: z.string(),
  sender: z.string(),
  sender_domain: z.string(),
  subject: z.string(),
  classification: z.string(),
  severity: z.string(),
  risk_score: z.number(),
  status: z.string(),
  attack_type: z.string(),
  duration_ms: z.number().nullable(),
})
export type AnalysisHistoryItem = z.infer<typeof AnalysisHistoryItemSchema>

export const AnalysisHistoryResponseSchema = z.object({
  items: z.array(AnalysisHistoryItemSchema),
  total_count: z.number(),
  page: z.number(),
  page_size: z.number(),
  total_pages: z.number(),
  has_next: z.boolean(),
  has_prev: z.boolean(),
})
export type AnalysisHistoryResponse = z.infer<typeof AnalysisHistoryResponseSchema>

