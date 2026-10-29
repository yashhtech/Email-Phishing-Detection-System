import { z } from 'zod'
import { RiskLevelSchema } from './email'

export const AnalysisStatusSchema = z.enum(['queued', 'analyzing', 'complete', 'failed', 'skipped'])
export type AnalysisStatus = z.infer<typeof AnalysisStatusSchema>

export const RiskFactorSchema = z.object({
  factor: z.string(),
  weight: z.number(),
  score: z.number(),
  description: z.string(),
})

export const AnalysisResultSchema = z.object({
  id: z.string(),
  email_id: z.string(),
  status: AnalysisStatusSchema,
  started_at: z.string().datetime({ offset: true }).nullable(),
  completed_at: z.string().datetime({ offset: true }).nullable(),
  duration_ms: z.number().nullable(),
  risk_score: z.number().min(0).max(100).nullable(),
  risk_level: RiskLevelSchema.nullable(),
  risk_factors: z.array(RiskFactorSchema),
  error_message: z.string().nullable(),
  retry_count: z.number(),
})

export type AnalysisResult = z.infer<typeof AnalysisResultSchema>
export type RiskFactor = z.infer<typeof RiskFactorSchema>
