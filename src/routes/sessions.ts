import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { refreshTokens } from "../db/schema";
import { eq, and, gt, desc } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate";
import { audit } from "../services/audit";
import { AppError } from "../utils/errors";

const router = Router();

router.use(authenticate);

/**
 * Sessions are self service: the user manages their own, identified
 * by their Bearer token. API keys have no sessions and are refused
 * (docs/contracts/sessions-and-tokens.md).
 */
function requireUser(req: Request): { sub: string; cid: string } {
  if (!req.user) {
    throw AppError.forbidden(
      "Sessions are managed with a user Bearer token",
      "BEARER_REQUIRED"
    );
  }
  return { sub: req.user.sub, cid: req.user.cid };
}

// ─── GET /sessions — the user's active sessions ───────────────────

router.get("/", async (req: Request, res: Response) => {
  const { sub } = requireUser(req);

  const sessions = await db
    .select({
      id: refreshTokens.id,
      ip: refreshTokens.ipAddress,
      userAgent: refreshTokens.userAgent,
      createdAt: refreshTokens.createdAt,
      expiresAt: refreshTokens.expiresAt,
    })
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.userId, sub),
        eq(refreshTokens.revoked, false),
        gt(refreshTokens.expiresAt, new Date())
      )
    )
    .orderBy(desc(refreshTokens.createdAt));

  res.json(sessions);
});

// ─── DELETE /sessions/:id — revoke one session ────────────────────

router.delete("/:id", async (req: Request, res: Response) => {
  const { sub, cid } = requireUser(req);
  const sessionId = z.string().uuid().parse(req.params.id);

  // Scoped to the caller: someone else's session id is a 404,
  // indistinguishable from one that never existed
  const [revoked] = await db
    .update(refreshTokens)
    .set({ revoked: true, revokedReason: "user_revoked" })
    .where(
      and(
        eq(refreshTokens.id, sessionId),
        eq(refreshTokens.userId, sub),
        eq(refreshTokens.revoked, false)
      )
    )
    .returning({ id: refreshTokens.id });

  if (!revoked) throw AppError.notFound("Session not found");

  await audit(req, {
    clientId: cid,
    action: "session.revoked",
    actorType: "user",
    actorId: sub,
    details: { scope: "one", sessionId },
  });

  res.json({ message: "Session revoked", id: revoked.id });
});

// ─── DELETE /sessions — logout everywhere ─────────────────────────

router.delete("/", async (req: Request, res: Response) => {
  const { sub, cid } = requireUser(req);

  const revoked = await db
    .update(refreshTokens)
    .set({ revoked: true, revokedReason: "user_revoked" })
    .where(
      and(eq(refreshTokens.userId, sub), eq(refreshTokens.revoked, false))
    )
    .returning({ id: refreshTokens.id });

  await audit(req, {
    clientId: cid,
    action: "session.revoked",
    actorType: "user",
    actorId: sub,
    details: { scope: "all", count: revoked.length },
  });

  res.json({ message: "All sessions revoked", count: revoked.length });
});

export default router;
