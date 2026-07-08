import { Router, Request, Response } from "express";
import { verifyAccessToken } from "../services/token";
import { hashApiKey, hasScope } from "../services/apiKey";
import { db } from "../db";
import { apiKeys, serviceAccounts } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { getServiceAccountPermissions } from "../services/serviceAccount";

const router = Router();

/**
 * POST /auth/verify
 *
 * The key integration point. Your other apps call this to validate tokens
 * without needing the JWT secret.
 *
 * Accepts either:
 *   { token: "eyJ..." }            → JWT verification
 *   { apiKey: "sk_a1b2c3d4_..." }  → API key verification
 *
 * Returns:
 *   { valid: true, user: { id, clientId, email, permissions } }
 *   { valid: true, apiKey: { clientId, scopes } }
 *   { valid: false, error: "..." }
 */
router.post("/", async (req: Request, res: Response) => {
  const { token, apiKey, requiredPermission } = req.body;

  // ─── JWT verification ─────────────────────────────────────
  if (token) {
    try {
      const payload = await verifyAccessToken(token);

      // Optional: check a specific permission
      if (requiredPermission) {
        const perms = payload.permissions || [];
        const [resource] = requiredPermission.split(":");
        const hasIt =
          perms.includes("*") ||
          perms.includes(requiredPermission) ||
          perms.includes(`${resource}:*`);

        if (!hasIt) {
          res.json({
            valid: true,
            authorized: false,
            error: `Missing permission: ${requiredPermission}`,
          });
          return;
        }
      }

      res.json({
        valid: true,
        authorized: true,
        user: {
          id: payload.sub,
          clientId: payload.cid,
          email: payload.email,
          permissions: payload.permissions,
        },
      });
      return;
    } catch (err: any) {
      res.json({
        valid: false,
        error: err.code === "ERR_JWT_EXPIRED" ? "Token expired" : "Invalid token",
      });
      return;
    }
  }

  // ─── API key verification ─────────────────────────────────
  if (apiKey) {
    const hash = hashApiKey(apiKey);

    const [key] = await db
      .select()
      .from(apiKeys)
      .where(and(eq(apiKeys.keyHash, hash), eq(apiKeys.revoked, false)))
      .limit(1);

    if (!key || (key.expiresAt && key.expiresAt < new Date())) {
      res.json({ valid: false, error: "Invalid or expired API key" });
      return;
    }

    let scopes = key.scopes || [];
    let serviceAccount:
      | { id: string; name: string; isActive: boolean }
      | undefined;

    if (key.serviceAccountId) {
      const [account] = await db
        .select({
          id: serviceAccounts.id,
          name: serviceAccounts.name,
          isActive: serviceAccounts.isActive,
        })
        .from(serviceAccounts)
        .where(
          and(
            eq(serviceAccounts.id, key.serviceAccountId),
            eq(serviceAccounts.clientId, key.clientId),
            eq(serviceAccounts.isActive, true)
          )
        )
        .limit(1);

      if (!account) {
        res.json({ valid: false, error: "Invalid or expired API key" });
        return;
      }

      serviceAccount = account;
      scopes = await getServiceAccountPermissions(account.id, key.clientId);
    }

    // Check scope if required
    if (requiredPermission && !hasScope(scopes, requiredPermission)) {
      res.json({
        valid: true,
        authorized: false,
        error: `API key missing scope: ${requiredPermission}`,
      });
      return;
    }

    // Update last used (fire-and-forget)
    db.update(apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiKeys.id, key.id))
      .execute()
      .catch(() => {});

    res.json({
      valid: true,
      authorized: true,
      apiKey: {
        clientId: key.clientId,
        name: key.name,
        scopes,
        ...(serviceAccount && {
          serviceAccount: {
            id: serviceAccount.id,
            name: serviceAccount.name,
          },
        }),
      },
    });
    return;
  }

  res.status(400).json({
    valid: false,
    error: "Provide either 'token' or 'apiKey' in request body",
  });
});

export default router;
