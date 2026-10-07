import { z } from 'zod';

export const actionSchema = z.enum(['ALLOW', 'WARN_AND_VERIFY', 'STEP_UP', 'ANALYST_REVIEW', 'UNKNOWN']);
export const decisionSchema = z.object({
  event_id: z.string().regex(/^evt_[a-z0-9_-]+$/),
  action: actionSchema,
  risk_band: z.string(),
  score: z.number().min(0).max(1).nullable(),
  score_kind: z.enum(['RISK_INDEX', 'CALIBRATED_PROBABILITY', 'NONE']),
  calibrated: z.boolean(),
  evidence_coverage: z.number().min(0).max(1),
  participation: z.string(),
  local_only: z.boolean(),
  consent_outcome: z.string(),
  engine_version: z.string(),
  calibration_status: z.string(),
  subject_event_time: z.string(),
  expires_at: z.string(),
  audit_id: z.string().nullable().optional(),
  unknown_reason: z.string().nullable().optional(),
  uncertainty: z.object({ level: z.string(), reasons: z.array(z.string()) }),
  reasons: z.array(z.object({ code: z.string(), feature: z.string(), value: z.unknown().optional() }).passthrough()),
}).passthrough().superRefine((decision, context) => {
  if (decision.action === 'UNKNOWN' && decision.score !== null) context.addIssue({ code: 'custom', message: 'UNKNOWN must not invent a score' });
  if (decision.score_kind === 'CALIBRATED_PROBABILITY' && (!decision.calibrated || decision.calibration_status !== 'FITTED')) context.addIssue({ code: 'custom', message: 'Probability requires fitted calibration' });
});
export type Decision = z.infer<typeof decisionSchema>;
export const receiptSchema = z.object({ effect: z.literal('recorded_only'), audit_id: z.string().regex(/^PAUD-/), action: z.string(), duplicate: z.boolean(), expires_at: z.string() }).passthrough();
export const sessionSchema = z.object({ user_id: z.string(), role: z.string(), institution: z.string(), permissions: z.array(z.string()) });
export type Session = z.infer<typeof sessionSchema>;
export const graphNodeSchema = z.object({ id: z.string().regex(/^case_/), label: z.string(), institution: z.string(), subject: z.boolean() });
export const graphEdgeSchema = z.object({ id: z.string(), source: z.string(), target: z.string(), amount_bucket: z.string(), occurred_at: z.string(), pending: z.boolean() });
export const evidenceSchema = z.object({ decision: decisionSchema, nodes: z.array(graphNodeSchema), edges: z.array(graphEdgeSchema), audit: z.array(z.record(z.unknown())), excluded_future_events: z.literal(true), event_source: z.string() }).passthrough();
export type Evidence = z.infer<typeof evidenceSchema>;
export type WorkspaceCase = Evidence & { id: string; title: string; institution: string; amount_bucket: string };

export class ApiError extends Error {
  constructor(message: string, public status: number | null = null) { super(message); }
}

export class WorkspaceClient {
  constructor(private readonly key: string) {}
  async request<Schema extends z.ZodTypeAny>(path: string, schema: Schema, options: RequestInit = {}): Promise<z.infer<Schema>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(path, { ...options, signal: controller.signal, headers: { 'X-API-Key': this.key, 'Content-Type': 'application/json' } });
      const payload = await response.json();
      if (!response.ok) throw new ApiError(typeof payload.detail === 'string' ? payload.detail : 'Request rejected', response.status);
      return schema.parse(payload);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(error instanceof Error ? error.message : 'Response unconfirmed');
    } finally { clearTimeout(timeout); }
  }
}

export function eligibleActions(decision: Decision, canReview: boolean, live: boolean): string[] {
  if (live && Date.parse(decision.expires_at) <= Date.now()) return [];
  const actions = ['DISPLAY'];
  if (!canReview || decision.action === 'ALLOW') return actions;
  actions.push('REVIEW', 'ESCALATE');
  if (['WARN_AND_VERIFY', 'STEP_UP'].includes(decision.action)) actions.push('STEP_UP');
  return actions;
}

export function definitiveRejection(error: unknown): boolean {
  return error instanceof ApiError && error.status !== null && error.status >= 400 && error.status < 500 && ![408, 429].includes(error.status);
}