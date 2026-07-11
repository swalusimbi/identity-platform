import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, TokenPayload } from "../services/token";
import { hashApiKey } from "../services/apiKey";
import { db } from "../db";
import { apiKeys, clients, serviceAccounts } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { AppError } from "../utils/errors";
import { getServiceAccountPermissions } from "../services/serviceAccount";

// Extend Express Request to carry auth context
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      apiKey?: {
        id: string;
        clientId: string;
        scopes: string[];
        serviceAccountId?: string;
        serviceAccountName?: string;
      };
    }
  }
}

/**
 * Client UUID of the authenticated principal, whether the request
 * carries a JWT (req.user) or an API key (req.apiKey)
 */
export function authenticatedClientId(req: Request): string {
  const clientId = req.user?.cid ?? req.apiKey?.clientId;
  if (!clientId) throw AppError.unauthorized("Authentication required");
  return clientId;
}

/**
 * Authenticate via Bearer token (JWT) or API key (sk_...)
 * Populates req.user (JWT) or req.apiKey (API key)
 */
export async function authenticate(
  req: Request,
  _res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader) throw AppError.unauthorized("Missing authorization header");

  const [scheme, token] = authHeader.split(" ");

  if (scheme === "Bearer" && token) {
    // JWT authentication
    try {
      req.user = await verifyAccessToken(token);
      return next();
    } catch {
      throw AppError.unauthorized("Invalid or expired token", "TOKEN_EXPIRED");
    }
  }

  if (scheme === "ApiKey" && token) {
    // API key authentication
    const hash = hashApiKey(token);
    const now = new Date();

    const [key] = await db
      .select()
      .from(apiKeys)
      .where(
        and(
          eq(apiKeys.keyHash, hash),
          eq(apiKeys.revoked, false)
        )
      )
      .limit(1);

    if (!key) throw AppError.unauthorized("Invalid API key");
    if (key.expiresAt && key.expiresAt < now)
      throw AppError.unauthorized("API key expired");

    // A deactivated client shuts its whole silo. API keys are checked
    // per request, so deactivation reaches them immediately, unlike
    // access tokens which ride out their TTL.
    const [owningClient] = await db
      .select({ isActive: clients.isActive })
      .from(clients)
      .where(eq(clients.id, key.clientId))
      .limit(1);

    if (!owningClient?.isActive) throw AppError.unauthorized("Invalid API key");

    let scopes = key.scopes || [];
    let serviceAccountName: string | undefined;

    if (key.serviceAccountId) {
      const [serviceAccount] = await db
        .select()
        .from(serviceAccounts)
        .where(
          and(
            eq(serviceAccounts.id, key.serviceAccountId),
            eq(serviceAccounts.clientId, key.clientId),
            eq(serviceAccounts.isActive, true)
          )
        )
        .limit(1);

      if (!serviceAccount) throw AppError.unauthorized("Invalid API key");
      scopes = await getServiceAccountPermissions(serviceAccount.id, key.clientId);
      serviceAccountName = serviceAccount.name;
    }

    // Update last used timestamp (fire-and-forget)
    db.update(apiKeys)
      .set({ lastUsedAt: now })
      .where(eq(apiKeys.id, key.id))
      .execute()
      .catch(() => {}); // Non-blocking

    req.apiKey = {
      id: key.id,
      clientId: key.clientId,
      scopes,
      serviceAccountId: key.serviceAccountId ?? undefined,
      serviceAccountName,
    };
    return next();
  }

  throw AppError.unauthorized("Invalid authorization scheme. Use: Bearer <jwt> or ApiKey <key>");
}

/**
 * Optional auth — doesn't throw if no token, but populates if present
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return next();

  try {
    await authenticate(req, res, next);
  } catch {
    next(); // Silently continue without auth
  }
}
