import { Request } from "express";
import { createHash, timingSafeEqual } from "crypto";
import { db } from "../db";
import {
  clients,
  refreshTokens,
  roles,
  userRoles,
  rolePermissions,
  permissions,
  Client,
} from "../db/schema";
import { eq, and } from "drizzle-orm";
import { createTokenPair, TokenPair } from "./token";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

/**
 * Validate app client credentials (cl_... / cs_...).
 * Confidential clients must present their secret. Public clients have
 * none, they are identified by client id alone and rely on PKCE plus
 * refresh token rotation.
 * Throws 401 INVALID_CLIENT when the client is unknown, inactive or
 * the secret doesn't match.
 */
export async function verifyClientCredentials(
  clientId: string,
  clientSecret?: string
): Promise<Client> {
  const [client] = await db
    .select()
    .from(clients)
    .where(and(eq(clients.clientId, clientId), eq(clients.isActive, true)))
    .limit(1);

  if (!client) {
    throw AppError.unauthorized("Invalid client credentials", "INVALID_CLIENT");
  }

  if (client.isPublic) return client;

  if (!clientSecret || !client.clientSecretHash) {
    throw AppError.unauthorized("Invalid client credentials", "INVALID_CLIENT");
  }

  const provided = createHash("sha256").update(clientSecret).digest("hex");
  const matches = timingSafeEqual(
    Buffer.from(provided),
    Buffer.from(client.clientSecretHash)
  );

  if (!matches) {
    throw AppError.unauthorized("Invalid client credentials", "INVALID_CLIENT");
  }

  return client;
}

/**
 * Load user's flattened permissions for a given client.
 * Walks: user → user_roles → roles → role_permissions → permissions
 * Returns: ["users:read", "billing:write", ...]
 */
export async function getUserPermissions(
  userId: string,
  clientId: string
): Promise<string[]> {
  const rows = await db
    .select({ resource: permissions.resource, action: permissions.action })
    .from(userRoles)
    .innerJoin(rolePermissions, eq(rolePermissions.roleId, userRoles.roleId))
    .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(and(eq(userRoles.userId, userId), eq(userRoles.clientId, clientId)));

  return rows.map((r) => `${r.resource}:${r.action}`);
}

/**
 * Auto-assign default role(s) for a client to a new user
 */
export async function assignDefaultRoles(
  userId: string,
  clientId: string
): Promise<void> {
  const defaultRoles = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.clientId, clientId), eq(roles.isDefault, true)));

  if (defaultRoles.length > 0) {
    await db.insert(userRoles).values(
      defaultRoles.map((r) => ({ userId, roleId: r.id, clientId }))
    );
  }
}

/**
 * Issue a session: build the access/refresh token pair with the user's
 * current permissions and persist the refresh token with request metadata.
 */
export async function issueSession(
  user: { id: string; email: string },
  clientUuid: string,
  req: Request
): Promise<TokenPair> {
  const perms = await getUserPermissions(user.id, clientUuid);
  const tokenPair = await createTokenPair({
    sub: user.id,
    cid: clientUuid,
    email: user.email,
    permissions: perms,
  });

  await db.insert(refreshTokens).values({
    userId: user.id,
    tokenHash: tokenPair.refreshTokenHash,
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
    expiresAt: new Date(
      Date.now() + env.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000
    ),
  });

  return {
    accessToken: tokenPair.accessToken,
    refreshToken: tokenPair.refreshToken,
    expiresIn: tokenPair.expiresIn,
  };
}
