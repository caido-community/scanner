import { z } from "zod";

import { ScanAggressivitySchema, SeveritySchema } from "./common";

const ScanConfigSchema = z.object({
  aggressivity: ScanAggressivitySchema,
  scopeIDs: z.array(z.string()).default([]),
  concurrentChecks: z.number().int().min(1).max(100),
  concurrentRequests: z.number().int().min(1).max(100),
  concurrentTargets: z.number().int().min(1).max(100),
  requestsDelayMs: z.number().int().min(0),
  scanTimeout: z.number().int().min(1),
  checkTimeout: z.number().int().min(1),
  requestTimeout: z.number().int().min(1).max(600).optional(),
  severities: z.array(SeveritySchema).min(1),
});

export const ScanRequestPayloadSchema = z.object({
  requestIDs: z.array(z.string().min(1)).min(1),
  scanConfig: ScanConfigSchema,
  title: z.string().min(1).max(100),
});

export const SessionTitleSchema = z.string().min(1).max(100);
