import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, TokenPayload } from "../services/token";
import { hashApiKey, hasScope } from "../services/apiKey";
import { db } from "../db";
import { apiKeys } from "../db/schema";
import { eq, and, isNull, gt } from "drizzle-orm";
import { AppError } from "../utils/errors";

// Extend Express Request to carry auth context
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      apiKey?: { clientId: string; scopes: string[] };
    }
  }
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

    // Update last used timestamp (fire-and-forget)
    db.update(apiKeys)
      .set({ lastUsedAt: now })
      .where(eq(apiKeys.id, key.id))
      .execute()
      .catch(() => {}); // Non-blocking

    req.apiKey = {
      clientId: key.clientId,
      scopes: key.scopes || [],
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
