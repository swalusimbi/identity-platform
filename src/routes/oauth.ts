import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, clients } from "../db/schema";
import { eq, and } from "drizzle-orm";
import {
  getProviderConfig,
  encryptState,
  decryptState,
  generateAuthCode,
  storeAuthCode,
  consumeAuthCode,
  resolveAuthCode,
  verifierMatchesChallenge,
  exchangeCodeForProviderToken,
  fetchProviderUserInfo,
} from "../services/oauth";
import {
  verifyClientCredentials,
  assignDefaultRoles,
  issueSession,
} from "../services/session";
import { audit } from "../services/audit";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

const router = Router();

// ─── Validation schemas ───────────────────────────────────────────

const initiateSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  // PKCE (RFC 7636). Only S256 is supported, required for public clients
  code_challenge: z.string().min(43).max(128).optional(),
  code_challenge_method: z.enum(["S256"]).optional(),
});

const tokenExchangeSchema = z.object({
  code: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
  redirectUri: z.string().url(),
  codeVerifier: z.string().min(43).max(128).optional(),
});

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

  // Check redirect_uri is registered for this client. Clients with no
  // registered URIs cannot use OAuth at all, otherwise any URI would be
  // accepted and the auth code could be sent to an attacker's domain.
  const allowedUris = client.redirectUris || [];
  if (!allowedUris.includes(query.redirect_uri)) {
    throw AppError.badRequest("redirect_uri not registered for this client");
  }

  // Public clients have no secret, PKCE is what binds the code to them
  if (client.isPublic && !query.code_challenge) {
    throw AppError.badRequest(
      "code_challenge is required for public clients",
      "PKCE_REQUIRED"
    );
  }

  // Encrypt state (contains client_id + redirect_uri + nonce + PKCE)
  const state = encryptState({
    clientId: query.client_id,
    redirectUri: query.redirect_uri,
    nonce: crypto.randomUUID(),
    codeChallenge: query.code_challenge,
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

    await audit(req, {
      clientId: client.id,
      action: "user.registered",
      actorType: "user",
      actorId: user.id,
      details: { method: provider },
    });
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
    codeChallenge: stateData.codeChallenge,
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

  // Resolve before consuming so failed binding checks do not burn a
  // legitimate code. The final consume below remains atomic.
  const codeData = await resolveAuthCode(body.code);
  if (!codeData) {
    throw AppError.unauthorized("Invalid or expired authorization code", "INVALID_CODE");
  }

  // Validate client credentials
  if (codeData.appClientId !== body.clientId) {
    throw AppError.unauthorized("Client ID mismatch", "CLIENT_MISMATCH");
  }

  const client = await verifyClientCredentials(body.clientId, body.clientSecret);
  if (codeData.clientId !== client.id) {
    throw AppError.unauthorized("Client ID mismatch", "CLIENT_MISMATCH");
  }

  // Validate redirect_uri matches
  if (codeData.redirectUri !== body.redirectUri) {
    throw AppError.unauthorized("redirect_uri mismatch");
  }

  // PKCE: a code issued with a challenge can only be redeemed with
  // the matching verifier
  if (codeData.codeChallenge) {
    if (!body.codeVerifier || !verifierMatchesChallenge(body.codeVerifier, codeData.codeChallenge)) {
      throw AppError.unauthorized("Invalid code verifier", "INVALID_VERIFIER");
    }
  }

  const consumedCode = await consumeAuthCode(body.code);
  if (!consumedCode) {
    throw AppError.unauthorized("Invalid or expired authorization code", "INVALID_CODE");
  }

  // Load user + permissions
  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, consumedCode.userId), eq(users.isActive, true)))
    .limit(1);

  if (!user) throw AppError.unauthorized("User not found or inactive");

  const session = await issueSession(user, client.id, req);

  await audit(req, {
    clientId: client.id,
    action: "user.login",
    actorType: "user",
    actorId: user.id,
    details: { method: user.oauthProvider ?? "oauth" },
  });

  res.json({
    user: { id: user.id, email: user.email },
    ...session,
  });
});

export default router;
