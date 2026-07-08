import { Request } from "express";
import { db } from "../db";
import { auditLogs } from "../db/schema";

export type AuditActorType =
  | "user"
  | "api_key"
  | "service_account"
  | "operator"
  | "anonymous";

export interface AuditEvent {
  clientId: string;
  action: string;
  actorType: AuditActorType;
  actorId?: string;
  targetType?:
    | "user"
    | "role"
    | "permission"
    | "api_key"
    | "service_account"
    | "client";
  targetId?: string;
  details?: Record<string, unknown>;
}

/**
 * Record an audit event for a request. Awaited so the row is visible
 * as soon as the response is, but a failed write never fails the
 * operation it describes: the platform stays available and the
 * failure is logged for the operator (docs/contracts/audit.md).
 */
export async function audit(req: Request, event: AuditEvent): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      clientId: event.clientId,
      action: event.action,
      actorType: event.actorType,
      actorId: event.actorId,
      targetType: event.targetType,
      targetId: event.targetId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      details: event.details,
    });
  } catch (err) {
    console.error(`Audit write failed for ${event.action}:`, err);
  }
}

/**
 * Resolve the acting principal from an authenticated request.
 * Use after authenticate(), where req.user or req.apiKey is set.
 */
export function auditActor(req: Request): {
  actorType: AuditActorType;
  actorId?: string;
} {
  if (req.user) return { actorType: "user", actorId: req.user.sub };
  if (req.apiKey?.serviceAccountId) {
    return {
      actorType: "service_account",
      actorId: req.apiKey.serviceAccountId,
    };
  }
  if (req.apiKey) return { actorType: "api_key", actorId: req.apiKey.id };
  return { actorType: "anonymous" };
}
