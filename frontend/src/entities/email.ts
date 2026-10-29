import { z } from 'zod'

export const EmailStatusSchema = z.enum(['queued', 'analyzing', 'complete', 'failed'])
export type EmailStatus = z.infer<typeof EmailStatusSchema>

export const RiskLevelSchema = z.enum(['critical', 'high', 'medium', 'low', 'safe'])
export type RiskLevel = z.infer<typeof RiskLevelSchema>

export const EmailSummarySchema = z.object({
  id: z.string(),
  message_id: z.string(),
  subject: z.string().nullable(),
  from_address: z.string(),
  from_domain: z.string(),
  received_at: z.string().datetime({ offset: true }),
  status: EmailStatusSchema,
  risk_score: z.number().min(0).max(100).nullable(),
  risk_level: RiskLevelSchema.nullable(),
  has_attachments: z.boolean(),
  source: z.string(),
  created_at: z.string().datetime({ offset: true }),
  analysis_id: z.string().nullable(),
  threat_categories: z.array(z.string()),
})

export type EmailSummary = z.infer<typeof EmailSummarySchema>
