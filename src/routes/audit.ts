import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { auditLogs } from "../db/schema";
import { eq, and, lt, gte, lte, desc, SQL } from "drizzle-orm";
import { authenticate, authenticatedClientId } from "../middleware/authenticate";
import { requirePermission } from "../middleware/authorize";

const router = Router();

router.use(authenticate);

const listSchema = z.object({
  action: z.string().max(64).optional(),
  actorId: z.string().uuid().optional(),
  targetId: z.string().uuid().optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  // Cursor: return rows strictly older than this timestamp
  before: z.coerce.date().optional(),
});

// ─── GET /audit — the client's history, newest first ──────────────
// Reads require a dedicated audit:read grant, deliberately not
// bundled into users:read (docs/contracts/audit.md)

router.get(
  "/",
  requirePermission("audit:read"),
  async (req: Request, res: Response) => {
    const query = listSchema.parse(req.query);
    const clientId = authenticatedClientId(req);

    const conditions: SQL[] = [eq(auditLogs.clientId, clientId)];
    if (query.action) conditions.push(eq(auditLogs.action, query.action));
    if (query.actorId) conditions.push(eq(auditLogs.actorId, query.actorId));
    if (query.targetId) conditions.push(eq(auditLogs.targetId, query.targetId));
    if (query.from) conditions.push(gte(auditLogs.createdAt, query.from));
    if (query.to) conditions.push(lte(auditLogs.createdAt, query.to));
    if (query.before) conditions.push(lt(auditLogs.createdAt, query.before));

    const rows = await db
      .select()
      .from(auditLogs)
      .where(and(...conditions))
      .orderBy(desc(auditLogs.createdAt))
      .limit(query.limit);

    res.json({
      entries: rows,
      // Pass as ?before= to fetch the next (older) page
      nextBefore:
        rows.length === query.limit
          ? rows[rows.length - 1].createdAt.toISOString()
          : null,
    });
  }
);

export default router;
