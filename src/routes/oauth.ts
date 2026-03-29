import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, clients, roles, userRoles, rolePermissions, permissions, refreshTokens } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { createTokenPair } from "../services/token";
import {
  getProviderConfig,
  encryptState,
  decryptState,
  generateAuthCode,
  storeAuthCode,
  consumeAuthCode,
  exchangeCodeForProviderToken,
  fetchProviderUserInfo,
} from "../services/oauth";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

const router = Router();

// ─── Validation schemas ───────────────────────────────────────────

const initiateSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
});

const tokenExchangeSchema = z.object({
  code: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  redirectUri: z.string().url(),
});

// ─── Helpers ──────────────────────────────────────────────────────

async function getUserPermissions(userId: string, clientId: string): Promise<string[]> {
  const rows = await db
    .select({ resource: permissions.resource, action: permissions.action })
    .from(userRoles)
    .innerJoin(rolePermissions, eq(rolePermissions.roleId, userRoles.roleId))
    .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(and(eq(userRoles.userId, userId), eq(userRoles.clientId, clientId)));

  return rows.map((r) => `${r.resource}:${r.action}`);
}

async function assignDefaultRoles(userId: string, clientId: string): Promise<void> {
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

// ─── GET /auth/oauth/:provider — initiate OAuth flow ──────────────
// Example: GET /auth/oauth/google?client_id=cl_...&redirect_uri=https://app.example.com/auth/callback

router.get("/:provider", async (req: Request, res: Response) => {
  const provider = req.params.provider as string;
  const query = initiateSchema.parse(req.query);

  // Validate the provider
  const config = getProviderConfig(provider);

  // Validate the client exists and redirect_uri is allowed
  const [client] = await db
    .select()
    .from(clients)
    .where(and(eq(clients.clientId, query.client_id), eq(clients.isActive, true)))
    .limit(1);

  if (!client) throw AppError.badRequest("Invalid client_id");

  // Check redirect_uri is registered for this client
  const allowedUris = client.redirectUris || [];
  if (allowedUris.length > 0 && !allowedUris.includes(query.redirect_uri)) {
    throw AppError.badRequest("redirect_uri not registered for this client");
  }

  // Encrypt state (contains client_id + redirect_uri + nonce)
  const state = encryptState({
    clientId: query.client_id,
    redirectUri: query.redirect_uri,
    nonce: crypto.randomUUID(),
  });

  // Build the OAuth authorization URL
  const callbackUrl = `${env.SERVICE_URL}/auth/oauth/${provider}/callback`;

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: callbackUrl,
    response_type: "code",
    scope: config.scopes.join(" "),
    state,
    ...(provider === "google" && { access_type: "offline", prompt: "consent" }),
  });

  res.redirect(`${config.authUrl}?${params.toString()}`);
});

// ─── GET /auth/oauth/:provider/callback — handle provider callback ─

router.get("/:provider/callback", async (req: Request, res: Response) => {
  const provider = req.params.provider as string;
  const { code, state, error } = req.query as Record<string, string>;

  // Handle OAuth errors (user denied, etc.)
  if (error) {
    // Try to decrypt state to get redirect_uri for error redirect
    try {
      const stateData = decryptState(state);
      const errorUrl = new URL(stateData.redirectUri);
      errorUrl.searchParams.set("error", error);
      res.redirect(errorUrl.toString());
      return;
    } catch {
      throw AppError.badRequest(`OAuth error: ${error}`);
    }
  }

  if (!code || !state) throw AppError.badRequest("Missing code or state");

  // Decrypt and validate state
  let stateData;
  try {
    stateData = decryptState(state);
  } catch {
    throw AppError.badRequest("Invalid or tampered state parameter");
  }

  // Find the client
  const [client] = await db
    .select()
    .from(clients)
    .where(and(eq(clients.clientId, stateData.clientId), eq(clients.isActive, true)))
    .limit(1);

  if (!client) throw AppError.badRequest("Invalid client");

  // Exchange code for provider access token
  const callbackUrl = `${env.SERVICE_URL}/auth/oauth/${provider}/callback`;
  const providerToken = await exchangeCodeForProviderToken(provider, code, callbackUrl);

  // Fetch user info from provider
  const userInfo = await fetchProviderUserInfo(provider, providerToken.access_token);

  // Find or create user
  let [user] = await db
    .select()
    .from(users)
    .where(
      and(
        eq(users.clientId, client.id),
        eq(users.email, userInfo.email.toLowerCase())
      )
    )
    .limit(1);

  if (!user) {
    // New user — create with OAuth provider info, no password
    [user] = await db
      .insert(users)
      .values({
        clientId: client.id,
        email: userInfo.email.toLowerCase(),
        oauthProvider: provider,
        oauthProviderId: userInfo.providerId,
        emailVerified: true, // Provider already verified the email
      })
      .returning();

    await assignDefaultRoles(user.id, client.id);
  } else if (!user.oauthProvider) {
    // Existing email/password user — link OAuth provider
    await db
      .update(users)
      .set({
        oauthProvider: provider,
        oauthProviderId: userInfo.providerId,
        emailVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, user.id));
  } else if (
    user.oauthProvider !== provider ||
    user.oauthProviderId !== userInfo.providerId
  ) {
    throw AppError.conflict(
      "Email is already linked to a different OAuth account",
      "OAUTH_ACCOUNT_MISMATCH"
    );
  }

  // Generate a short-lived authorization code
  const authCode = generateAuthCode();
  await storeAuthCode(authCode, {
    userId: user.id,
    clientId: client.id,
    appClientId: stateData.clientId,
    redirectUri: stateData.redirectUri,
  });

  // Redirect back to the client app with the code
  const redirectUrl = new URL(stateData.redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  res.redirect(redirectUrl.toString());
});

// ─── POST /auth/oauth/token — exchange auth code for tokens ───────
// The client app's backend calls this with the code + client credentials

router.post("/token", async (req: Request, res: Response) => {
  const body = tokenExchangeSchema.parse(req.body);

  // Consume the authorization code (one-use)
  const codeData = await consumeAuthCode(body.code);
  if (!codeData) {
    throw AppError.unauthorized("Invalid or expired authorization code", "INVALID_CODE");
  }

  // Validate client credentials
  if (codeData.appClientId !== body.clientId) {
    throw AppError.unauthorized("Client ID mismatch", "CLIENT_MISMATCH");
  }

  // Verify client secret
  const { createHash } = await import("crypto");
  const secretHash = createHash("sha256").update(body.clientSecret).digest("hex");

  const [client] = await db
    .select()
    .from(clients)
    .where(
      and(
        eq(clients.clientId, body.clientId),
        eq(clients.clientSecretHash, secretHash),
        eq(clients.isActive, true)
      )
    )
    .limit(1);

  if (!client) throw AppError.unauthorized("Invalid client credentials");

  // Validate redirect_uri matches
  if (codeData.redirectUri !== body.redirectUri) {
    throw AppError.unauthorized("redirect_uri mismatch");
  }

  // Load user + permissions
  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, codeData.userId), eq(users.isActive, true)))
    .limit(1);

  if (!user) throw AppError.unauthorized("User not found or inactive");

  const perms = await getUserPermissions(user.id, client.id);
  const tokenPair = await createTokenPair({
    sub: user.id,
    cid: client.id,
    email: user.email,
    permissions: perms,
  });

  // Store refresh token
  await db.insert(refreshTokens).values({
    userId: user.id,
    tokenHash: tokenPair.refreshTokenHash,
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
    expiresAt: new Date(
      Date.now() + env.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000
    ),
  });

  res.json({
    user: { id: user.id, email: user.email },
    accessToken: tokenPair.accessToken,
    refreshToken: tokenPair.refreshToken,
    expiresIn: tokenPair.expiresIn,
  });
});

export default router;
