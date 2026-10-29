import { z } from 'zod'

export const ReportEmailMetadataSchema = z.object({
  email_id: z.string(),
  message_id: z.string().nullable(),
  from_address: z.string(),
  from_domain: z.string().nullable(),
  to_addresses: z.array(z.string()),
  cc_addresses: z.array(z.string()),
  reply_to: z.string().nullable(),
  subject: z.string().nullable(),
  received_at: z.string(),
  has_attachments: z.boolean(),
  attachment_count: z.number(),
  url_count: z.number(),
  spf_status: z.string().nullable(),
  dkim_status: z.string().nullable(),
  dmarc_status: z.string().nullable(),
  return_path: z.string().nullable(),
})
export type ReportEmailMetadata = z.infer<typeof ReportEmailMetadataSchema>

export const ReportRiskScoreSchema = z.object({
  overall_risk_score: z.number(),
  risk_level: z.string(),
  composite_score: z.number(),
  scoring_version: z.string(),
  spf_subscore: z.number(),
  dkim_subscore: z.number(),
  dmarc_subscore: z.number(),
  ml_subscore: z.number(),
  url_subscore: z.number(),
  attachment_subscore: z.number(),
  sender_reputation_subscore: z.number(),
  factor_breakdown: z.array(z.record(z.unknown())).nullable(),
})
export type ReportRiskScore = z.infer<typeof ReportRiskScoreSchema>

export const ReportClassificationSchema = z.object({
  verdict: z.string(),
  status: z.string(),
  primary_attack_type: z.string(),
  severity: z.string(),
  confidence: z.number(),
})
export type ReportClassification = z.infer<typeof ReportClassificationSchema>

export const ReportSecuritySignalSchema = z.object({
  id: z.string(),
  signal_type: z.string(),
  category: z.string(),
  severity: z.string(),
  attack_type: z.string(),
  confidence: z.number(),
  source: z.string(),
  title: z.string(),
  description: z.string(),
  indicator_value: z.string().nullable(),
})
export type ReportSecuritySignal = z.infer<typeof ReportSecuritySignalSchema>

export const ReportMLAnalysisSchema = z.object({
  model_name: z.string(),
  model_version: z.string(),
  classification: z.string(),
  confidence: z.number(),
  phishing_probability: z.number(),
  spam_probability: z.number(),
  malware_probability: z.number(),
  latency_ms: z.number().nullable(),
})
export type ReportMLAnalysis = z.infer<typeof ReportMLAnalysisSchema>

export const ReportGroqAnalysisSchema = z.object({
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
export type ReportGroqAnalysis = z.infer<typeof ReportGroqAnalysisSchema>

export const ReportThreatIntelligenceSchema = z.object({
  indicator_type: z.string(),
  indicator_value: z.string(),
  provider: z.string(),
  reputation: z.string(),
  threat_score: z.number().nullable(),
  tags: z.array(z.string()),
  last_checked_at: z.string(),
})
export type ReportThreatIntelligence = z.infer<typeof ReportThreatIntelligenceSchema>

export const ReportEvidenceItemSchema = z.object({
  title: z.string(),
  severity: z.string(),
  source: z.string(),
  category: z.string(),
  attack_type: z.string(),
  description: z.string(),
  indicator_value: z.string().nullable(),
  confidence: z.number(),
  why_it_matters: z.string(),
})
export type ReportEvidenceItem = z.infer<typeof ReportEvidenceItemSchema>

export const ReportTimestampsSchema = z.object({
  email_received_at: z.string().nullable(),
  analysis_started_at: z.string().nullable(),
  analysis_completed_at: z.string().nullable(),
  report_generated_at: z.string(),
  duration_ms: z.number().nullable(),
})
export type ReportTimestamps = z.infer<typeof ReportTimestampsSchema>

export const AnalysisReportSchema = z.object({
  report_id: z.string(),
  analysis_id: z.string(),
  org_id: z.string(),
  org_name: z.string().nullable(),
  engine_version: z.string(),
  scoring_version: z.string(),
  classification: ReportClassificationSchema,
  risk_score: ReportRiskScoreSchema,
  email_metadata: ReportEmailMetadataSchema,
  security_signals: z.array(ReportSecuritySignalSchema),
  ml_analysis: ReportMLAnalysisSchema.nullable(),
  groq_analysis: ReportGroqAnalysisSchema.nullable(),
  threat_intelligence: z.array(ReportThreatIntelligenceSchema),
  evidence: z.array(ReportEvidenceItemSchema),
  timestamps: ReportTimestampsSchema,
  generated_by: z.string(),
  confidentiality: z.string(),
})
export type AnalysisReport = z.infer<typeof AnalysisReportSchema>
