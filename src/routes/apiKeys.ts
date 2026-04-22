import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { apiKeys } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate";
import { requirePermission } from "../middleware/authorize";
import { generateApiKey } from "../services/apiKey";
import { AppError } from "../utils/errors";

const router = Router();

router.use(authenticate);

const createKeySchema = z.object({
  name: z.string().min(1).max(255),
  scopes: z.array(z.string()).default([]),
  expiresInDays: z.number().int().min(1).max(365).optional(),
});

// ─── POST /api-keys — generate a new key ──────────────────────────

router.post(
  "/",
  requirePermission("api-keys:write"),
  async (req: Request, res: Response) => {
    const body = createKeySchema.parse(req.body);
    const clientId = req.user!.cid;

    const { key, prefix, hash } = generateApiKey();

    const expiresAt = body.expiresInDays
      ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000)
      : null;

    const [created] = await db
      .insert(apiKeys)
      .values({
        clientId,
        keyPrefix: prefix,
        keyHash: hash,
        name: body.name,
        scopes: body.scopes,
        expiresAt,
      })
      .returning({
        id: apiKeys.id,
        name: apiKeys.name,
        keyPrefix: apiKeys.keyPrefix,
        scopes: apiKeys.scopes,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
      });

    // Return the full key ONCE — it's never stored or retrievable again
    res.status(201).json({
      ...created,
      key, // ← This is the only time the full key is visible
      warning: "Store this key securely. It cannot be retrieved again.",
    });
  }
);

// ─── GET /api-keys — list keys (prefix only, no secrets) ─────────

router.get(
  "/",
  requirePermission("api-keys:read"),
  async (req: Request, res: Response) => {
    const clientId = req.user!.cid;

    const keys = await db
      .select({
        id: apiKeys.id,
        name: apiKeys.name,
        keyPrefix: apiKeys.keyPrefix,
        scopes: apiKeys.scopes,
        revoked: apiKeys.revoked,
        expiresAt: apiKeys.expiresAt,
        lastUsedAt: apiKeys.lastUsedAt,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.clientId, clientId));

    res.json(keys);
  }
);

// ─── DELETE /api-keys/:id — revoke a key ──────────────────────────

router.delete(
  "/:id",
  requirePermission("api-keys:write"),
  async (req: Request, res: Response) => {
    const clientId = req.user!.cid;
    const keyId = z.string().uuid().parse(req.params.id);

    const [revoked] = await db
      .update(apiKeys)
      .set({ revoked: true })
      .where(
        and(eq(apiKeys.id, keyId), eq(apiKeys.clientId, clientId))
      )
      .returning({ id: apiKeys.id });

    if (!revoked) throw AppError.notFound("API key not found");
    res.json({ message: "API key revoked", id: revoked.id });
  }
);

export default router;
