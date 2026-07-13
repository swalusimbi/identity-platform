/**
 * Identity Platform Client SDK
 *
 * Drop this file into any of your apps
 * to integrate with your Identity Platform deployment
 *
 * Required dependency:
 *   npm install jose
 *
 * Usage:
 *   import { createAuthClient, requirePermission } from "./lib/auth";
 *
 *   const auth = createAuthClient({
 *     serviceUrl: "https://auth.example.com",
 *     clientId: process.env.AUTH_CLIENT_ID!,
 *     clientSecret: process.env.AUTH_CLIENT_SECRET!,
 *     redirectUri: "https://app.example.com/auth/callback",
 *   });
 *
 *   // Protect a route
 *   router.get("/dashboard", auth.requireAuth, (req, res) => {
 *     console.log(req.user); // { id, clientId, email, permissions }
 *   });
 *
 *   // Require specific permission
 *   router.delete("/users/:id", auth.requireAuth, requirePermission("users:delete"), handler);
 *
 *   // Machine callers: plain API keys and service account keys
 *   router.post("/reports", auth.requireApiKey, requirePermission("reports:write"), (req, res) => {
 *     console.log(req.principal); // { kind: "service_account", name, permissions, ... }
 *   });
 *
 *   // Humans and machines on one route
 *   router.get("/notes", auth.requirePrincipal, requirePermission("notes:read"), handler);
 *
 * Errors: every non-ok platform response throws AuthApiError (status,
 * code, details, rateLimit). Network failures, timeouts and malformed
 * response bodies throw AuthTransportError instead. A caller's own
 * AbortSignal surfaces as its AbortError, not wrapped. In the
 * middleware, a verification that cannot get an answer (transport, 5xx
 * or 429) answers 503, never 401.
 *
 * Retries: verifyTokenRemote and verifyApiKey are safe to retry.
 * refreshToken may be retried only after an AuthTransportError and
 * only with the same operationId. Nothing else is safe to retry
 * automatically, and this SDK never retries on its own.
 *
 * Legacy HS256 tokens are rejected locally unless allowLegacyHs256 is
 * set, which routes them to remote verification during a migration.
 *
 *   // OAuth login redirect with login-CSRF protection
 *   router.get("/login/google", (req, res) => {
 *     const state = auth.createOAuthState();
 *     req.session.oauthState = state;
 *     res.redirect(auth.getOAuthUrl("google", { state }));
 *   });
 *
 *   // OAuth callback: compare the one-time state before exchanging
 *   router.get("/auth/callback", async (req, res) => {
 *     const expected = req.session.oauthState;
 *     req.session.oauthState = undefined;
 *     if (!expected || req.query.state !== expected) {
 *       return res.status(400).send("OAuth state mismatch");
 *     }
 *     const tokens = await auth.exchangeOAuthCode(String(req.query.code));
 *     // Set cookies, redirect to dashboard, etc.
 *   });
 *
 * A default instance configured from env vars (AUTH_SERVICE_URL,
 * AUTH_ISSUER, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, AUTH_REDIRECT_URI)
 * is exported as `authClient` with its `requireAuth` middleware.
 */

import { Request, Response, NextFunction } from "express";

// The express import shadows the global fetch Response type, so the
// network layer names it explicitly
type FetchResponse = Awaited<ReturnType<typeof fetch>>;
import { createHash, randomBytes, randomUUID } from "crypto";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

// ─── Configuration ────────────────────────────────────────────────

export interface AuthClientConfig {
  serviceUrl: string;    // https://auth.example.com, trailing slashes are normalized away
  issuer?: string;       // defaults to the serviceUrl hostname
  // The EXTERNAL application id (cl_...) from registration. Not the
  // internal client UUID, which is what appears as `cid` in tokens.
  clientId: string;
  clientSecret?: string; // cs_... (keep server-side only), absent for public clients
  redirectUri?: string;  // https://app.example.com/auth/callback
  // Every platform request aborts after this long (default 10000 ms)
  // and surfaces as AuthTransportError
  requestTimeoutMs?: number;
  // Send legacy HS256 tokens to remote verification. Off by default:
  // without it an HS256 token is rejected locally with no platform
  // call, so garbage HS256 tokens cannot amplify into request volume.
  // Enable only while migrating consumers off legacy tokens.
  allowLegacyHs256?: boolean;
}

/** Optional per call controls, accepted by every network method */
export interface RequestOptions {
  signal?: AbortSignal;
}

// ─── Types ────────────────────────────────────────────────────────

/**
 * Thrown for every non-ok platform response. Carries the HTTP status
 * and the platform's machine readable code (INVALID_CREDENTIALS,
 * REGISTRATION_DISABLED, ...) so apps can forward or branch on the
 * real failure instead of a flattened message.
 */
export class AuthApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
    /** Field level issues from 400 VALIDATION_ERROR responses */
    public details?: unknown,
    /** Populated on 429 responses from the X-RateLimit-* headers */
    public rateLimit?: { limit?: number; remaining?: number; resetAt?: Date }
  ) {
    super(message);
    this.name = "AuthApiError";
  }
}

/**
 * The platform gave no usable answer: network failure, timeout or a
 * non JSON response. Distinct from AuthApiError, where the platform
 * answered and the answer was a refusal. Transport failures are the
 * only case where retrying a refresh (with the SAME operationId) is
 * correct, everything else must not be retried automatically.
 */
export class AuthTransportError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AuthTransportError";
  }
}

export interface AuthUser {
  id: string;
  clientId: string;
  email: string;
  permissions: string[];
}

/** A machine caller: a plain API key or a service account's key */
export interface MachinePrincipal {
  kind: "api_key" | "service_account";
  clientId: string;
  name: string;
  /** Scopes for plain keys, resolved role permissions for service accounts */
  permissions: string[];
  serviceAccountId?: string;
  serviceAccountName?: string;
}

export type UserPrincipal = AuthUser & { kind: "user" };

/** Whatever authenticated the request, human or machine */
export type Principal = UserPrincipal | MachinePrincipal;

export interface TokenResponse {
  user: { id: string; email: string };
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// /auth/refresh rotates the token pair but does not return the user
export type RefreshResponse = Omit<TokenResponse, "user">;

export interface VerifyResponse {
  valid: boolean;
  /** Only meaningful when valid is true and a permission was required */
  authorized?: boolean;
  user?: AuthUser;
  apiKey?: {
    clientId: string;
    name: string;
    scopes: string[];
    serviceAccount?: { id: string; name: string };
  };
  error?: string;
}

interface AuthJwtPayload extends JWTPayload {
  sub: string;
  cid: string;
  email: string;
  permissions?: string[];
}

// Extend Express Request
declare global {
  namespace Express {
    interface IdentityPlatformUser extends AuthUser {}

    interface Request {
      user?: IdentityPlatformUser;
      principal?: Principal;
    }
  }
}

/**
 * Read the token header's alg without verifying anything. Only used
 * to recognize legacy HS256 tokens, never as a trust decision.
 */
function tokenHeaderAlg(token: string): string | undefined {
  try {
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64url").toString("utf8")
    );
    return typeof header.alg === "string" ? header.alg : undefined;
  } catch {
    return undefined;
  }
}

// ─── Factory ──────────────────────────────────────────────────────

export type AuthClient = ReturnType<typeof createAuthClient>;

export function createAuthClient(config: AuthClientConfig) {
  // Fail fast on configuration that can only ever produce confusing
  // runtime errors later
  if (!config.serviceUrl) {
    throw new Error("auth-client: serviceUrl is required");
  }
  if (!config.clientId) {
    throw new Error(
      "auth-client: clientId is required, the cl_... id from registering this application"
    );
  }

  const serviceUrl = config.serviceUrl.replace(/\/+$/, "");
  const issuer = config.issuer ?? new URL(serviceUrl).hostname;
  const requestTimeoutMs = config.requestTimeoutMs ?? 10_000;

  // Keys are fetched lazily on first verification, then cached in-process
  const jwks = createRemoteJWKSet(
    new URL(`${serviceUrl}/.well-known/jwks.json`),
    {
      cacheMaxAge: 5 * 60 * 1000,
      cooldownDuration: 30 * 1000,
    }
  );

  /**
   * Every platform request goes through here: bounded by the
   * configured timeout, cancellable by the caller's signal, and
   * network level failures surface as AuthTransportError.
   */
  async function platformFetch(
    path: string,
    init: RequestInit,
    opts: RequestOptions = {}
  ): Promise<FetchResponse> {
    const signals = [AbortSignal.timeout(requestTimeoutMs)];
    if (opts.signal) signals.push(opts.signal);
    try {
      return await fetch(`${serviceUrl}${path}`, {
        ...init,
        signal: AbortSignal.any(signals),
      });
    } catch (err) {
      // Caller cancellation stays distinguishable: rethrow the caller's
      // own abort unchanged so it surfaces as an AbortError, not as a
      // platform transport failure. Only the timeout and genuine network
      // errors become AuthTransportError.
      if (opts.signal?.aborted) throw err;
      throw new AuthTransportError(
        "Request to the identity platform failed or timed out",
        { cause: err }
      );
    }
  }

  /**
   * Parse a successful response body. A malformed or truncated body is
   * an ambiguous transport outcome, not a platform refusal, so it
   * surfaces as AuthTransportError. This matters most for refresh: a
   * lost body after the server committed the rotation must be retried
   * with the same operationId, never treated as a definitive answer.
   */
  async function parseJson<T>(
    res: FetchResponse,
    opts: RequestOptions = {}
  ): Promise<T> {
    try {
      return (await res.json()) as T;
    } catch (err) {
      if (opts.signal?.aborted) throw err;
      throw new AuthTransportError(
        "The identity platform returned a malformed response",
        { cause: err }
      );
    }
  }

  /** Parse a non-ok platform response into a typed AuthApiError */
  async function toApiError(res: FetchResponse, errorLabel: string): Promise<AuthApiError> {
    const err = (await res.json().catch(() => ({}))) as {
      error?: string;
      code?: string;
      details?: unknown;
    };
    const rateLimit =
      res.status === 429
        ? {
            limit: Number(res.headers.get("x-ratelimit-limit")) || undefined,
            remaining: Number(res.headers.get("x-ratelimit-remaining")) || 0,
            resetAt: res.headers.get("x-ratelimit-reset")
              ? new Date(Number(res.headers.get("x-ratelimit-reset")) * 1000)
              : undefined,
          }
        : undefined;
    return new AuthApiError(
      err.error || `${errorLabel}: ${res.status}`,
      res.status,
      err.code,
      err.details,
      rateLimit
    );
  }

  async function post<T>(
    path: string,
    body: unknown,
    errorLabel: string,
    opts: RequestOptions = {}
  ): Promise<T> {
    const res = await platformFetch(
      path,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
      opts
    );

    if (!res.ok) throw await toApiError(res, errorLabel);

    return parseJson<T>(res, opts);
  }

  function clientCredentials() {
    return {
      clientId: config.clientId,
      // Omitted for public clients, the service knows they have none
      ...(config.clientSecret && { clientSecret: config.clientSecret }),
    };
  }

  /**
   * Verify a JWT locally using the platform JWKS endpoint.
   * This avoids a network call to /auth/verify on every request.
   */
  async function verifyTokenLocally(token: string): Promise<AuthUser> {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: config.clientId,
    });

    const authPayload = payload as AuthJwtPayload;
    return {
      id: authPayload.sub,
      clientId: authPayload.cid,
      email: authPayload.email,
      permissions: authPayload.permissions || [],
    };
  }

  /**
   * Verify a JWT or API key with the platform.
   *
   * Prefer verifyTokenLocally() for normal Bearer JWT requests.
   * Use this for API keys, legacy HS256 tokens, or explicit fallback.
   */
  async function verifyTokenRemote(
    token: string,
    requiredPermission?: string,
    opts: RequestOptions = {}
  ): Promise<VerifyResponse> {
    const res = await platformFetch(
      "/auth/verify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token,
          audience: config.clientId,
          requiredPermission,
        }),
      },
      opts
    );

    // Verification outcomes are 200s with valid true or false. A non
    // ok status means the request itself was refused
    if (!res.ok) throw await toApiError(res, "Verification failed");

    return parseJson<VerifyResponse>(res, opts);
  }

  async function verifyApiKey(
    apiKey: string,
    requiredPermission?: string,
    opts: RequestOptions = {}
  ): Promise<VerifyResponse> {
    const res = await platformFetch(
      "/auth/verify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apiKey,
          audience: config.clientId,
          requiredPermission,
        }),
      },
      opts
    );
    if (!res.ok) throw await toApiError(res, "Verification failed");
    return parseJson<VerifyResponse>(res, opts);
  }


  /**
   * Middleware: require a valid access token
   *
   * Extracts Bearer token from Authorization header,
   * verifies the JWT locally via JWKS, populates req.user
   */
  const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({ error: "Missing authorization header" });
        return;
      }

      const token = authHeader.split(" ")[1];

      try {
        req.user = await verifyTokenLocally(token) as Express.IdentityPlatformUser;
        req.principal = { kind: "user", ...req.user };
        next();
      } catch (err) {
        // Local verification is authoritative: expired, tampered,
        // wrong-issuer, wrong-audience and malformed tokens are final
        // here, so invalid-token traffic never amplifies into platform
        // requests. The remote path exists only for legacy HS256
        // tokens (opt in) and for JWKS availability failures where no
        // local answer is possible.
        const code = (err as { code?: string }).code ?? "";
        const legacyHs256 =
          config.allowLegacyHs256 === true && tokenHeaderAlg(token) === "HS256";
        const jwksUnavailable =
          code === "ERR_JWKS_TIMEOUT" ||
          code === "ERR_JWKS_INVALID" ||
          code === "ERR_JOSE_GENERIC" ||
          !code.startsWith("ERR_");

        if (!legacyHs256 && !jwksUnavailable) {
          res.status(401).json({ error: "Invalid token" });
          return;
        }

        try {
          const result = await verifyTokenRemote(token);

          if (!result.valid || !result.user) {
            res.status(401).json({ error: result.error || "Invalid token" });
            return;
          }

          req.user = result.user as Express.IdentityPlatformUser;
          req.principal = { kind: "user", ...result.user };
          next();
        } catch (remoteErr) {
          // A thrown error means we could not GET a verification
          // answer, an availability problem, never "the token is
          // invalid". Mapping it to 401 would lie about what failed.
          respondPlatformUnavailable(res, remoteErr);
        }
      }
  };

  /**
   * Middleware: require a machine credential, `ApiKey sk_...`.
   * API keys are database state, so verification is always remote.
   * Populates req.principal with the key or its service account.
   */
  const requireApiKey = async (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("ApiKey ")) {
        res.status(401).json({ error: "Missing API key" });
        return;
      }

      try {
        const result = await verifyApiKey(authHeader.split(" ")[1]);

        if (!result.valid || !result.apiKey) {
          res.status(401).json({ error: result.error || "Invalid API key" });
          return;
        }

        req.principal = {
          kind: result.apiKey.serviceAccount ? "service_account" : "api_key",
          clientId: result.apiKey.clientId,
          name: result.apiKey.name,
          permissions: result.apiKey.scopes,
          serviceAccountId: result.apiKey.serviceAccount?.id,
          serviceAccountName: result.apiKey.serviceAccount?.name,
        };
        next();
      } catch (err) {
        // As with tokens: a thrown error is an availability problem,
        // not a rejected key. A rejected key is the valid:false branch
        // above, which is the only 401 path.
        respondPlatformUnavailable(res, err);
      }
  };

  /**
   * Middleware: accept either principal kind, dispatching on the
   * authorization scheme. Use requirePermission after it for routes
   * that serve humans and machines alike.
   */
  const requirePrincipal = async (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization ?? "";
      if (authHeader.startsWith("Bearer ")) {
        return requireAuth(req, res, next);
      }
      if (authHeader.startsWith("ApiKey ")) {
        return requireApiKey(req, res, next);
      }
      res.status(401).json({
        error: "Invalid authorization scheme. Use: Bearer <jwt> or ApiKey <key>",
      });
  };

  return {
    config,

    verifyTokenLocally,
    verifyTokenRemote,

    createRefreshOperationId: randomUUID,

    /**
     * One-time value for OAuth login CSRF protection. Store it in the
     * user's session before redirecting, pass it to getOAuthUrl and
     * compare it with the `state` query parameter on your callback.
     * Reject the callback and clear the stored value on any mismatch.
     */
    createOAuthState: randomUUID,

    /**
     * PKCE material for an OAuth transaction (RFC 7636, S256).
     * Send the challenge with getOAuthUrl, keep the verifier with the
     * same one-time state and pass it to exchangeOAuthCode. Required
     * for public clients, supported for confidential ones.
     */
    createPkcePair(): { verifier: string; challenge: string } {
      const verifier = randomBytes(48).toString("base64url");
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      return { verifier, challenge };
    },

    /**
     * Build the OAuth redirect URL for a provider
     * Redirect the user's browser to this URL to start OAuth.
     * Public clients must pass a PKCE S256 codeChallenge.
     */
    getOAuthUrl(
      provider: "google" | "github",
      opts: { codeChallenge?: string; state?: string } = {}
    ): string {
      if (!config.redirectUri) {
        throw new Error("redirectUri is required for OAuth flows");
      }
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        ...(opts.codeChallenge && {
          code_challenge: opts.codeChallenge,
          code_challenge_method: "S256",
        }),
        ...(opts.state && { state: opts.state }),
      });
      return `${serviceUrl}/auth/oauth/${provider}?${params}`;
    },

    /**
     * Exchange an OAuth authorization code for tokens
     * Call this from your /auth/callback route handler.
     * Pass the PKCE codeVerifier when the flow started with a challenge.
     */
    exchangeOAuthCode(
      code: string,
      opts: { codeVerifier?: string } & RequestOptions = {}
    ): Promise<TokenResponse> {
      return post("/auth/oauth/token", {
        code,
        redirectUri: config.redirectUri,
        ...(opts.codeVerifier && { codeVerifier: opts.codeVerifier }),
        ...clientCredentials(),
      }, "Token exchange failed", opts);
    },

    /**
     * Verify an API key with the platform.
     * API keys are opaque and cannot be verified through JWKS.
     */
    verifyApiKey,

    /**
     * Refresh an access token using a refresh token
     * Use a fresh operationId for new work. Reuse it only when retrying
     * the same old token after an ambiguous transport result.
     */
    refreshToken(
      refreshToken: string,
      operationId: string,
      opts: RequestOptions = {}
    ): Promise<RefreshResponse> {
      return post("/auth/refresh", {
        refreshToken,
        operationId,
        ...clientCredentials(),
      }, "Refresh failed", opts);
    },

    /**
     * Register a new user (email/password)
     */
    register(
      email: string,
      password: string,
      opts: RequestOptions = {}
    ): Promise<TokenResponse> {
      return post("/auth/register", {
        email,
        password,
        ...clientCredentials(),
      }, "Registration failed", opts);
    },

    /**
     * Login with email/password
     */
    login(
      email: string,
      password: string,
      opts: RequestOptions = {}
    ): Promise<TokenResponse> {
      return post("/auth/login", {
        email,
        password,
        ...clientCredentials(),
      }, "Login failed", opts);
    },

    /**
     * Request a password reset email. The link points at the page
     * registered on the client (passwordResetUrl). Always resolves,
     * the service never reveals whether the email exists.
     */
    async forgotPassword(email: string, opts: RequestOptions = {}): Promise<void> {
      await post("/auth/password/forgot", {
        email,
        ...clientCredentials(),
      }, "Password reset request failed", opts);
    },

    /**
     * Complete a password reset with the token from the email link.
     * All of the user's sessions are revoked.
     */
    async resetPassword(
      token: string,
      newPassword: string,
      opts: RequestOptions = {}
    ): Promise<void> {
      await post("/auth/password/reset", {
        token,
        newPassword,
        ...clientCredentials(),
      }, "Password reset failed", opts);
    },

    /**
     * Change the password of the logged in user. Revokes all sessions,
     * log in again afterwards.
     */
    async changePassword(
      accessToken: string,
      currentPassword: string,
      newPassword: string,
      opts: RequestOptions = {}
    ): Promise<void> {
      const res = await platformFetch(
        "/auth/password/change",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({ currentPassword, newPassword }),
        },
        opts
      );
      if (!res.ok) throw await toApiError(res, "Password change failed");
    },

    /**
     * Send an email verification link. The link points at the page
     * registered on the client (emailVerifyUrl).
     */
    async sendEmailVerification(
      email: string,
      opts: RequestOptions = {}
    ): Promise<void> {
      await post("/auth/email/send-verification", {
        email,
        ...clientCredentials(),
      }, "Verification request failed", opts);
    },

    /**
     * Confirm an email with the token from the verification link
     */
    async verifyEmail(token: string, opts: RequestOptions = {}): Promise<void> {
      await post("/auth/email/verify", {
        token,
        ...clientCredentials(),
      }, "Email verification failed", opts);
    },

    /**
     * Logout (revoke refresh token). Throws on failure like every
     * other call, a failed logout must never look successful.
     */
    async logout(refreshToken: string, opts: RequestOptions = {}): Promise<void> {
      await post(
        "/auth/logout",
        { refreshToken, ...clientCredentials() },
        "Logout failed",
        opts
      );
    },

    requireAuth,
    requireApiKey,
    requirePrincipal,
  };
}

// ─── Default instance from env ────────────────────────────────────

// Constructed on first use, not at import: apps that build their own
// client with createAuthClient() must be able to import this module
// without AUTH_* variables set, and configuration errors should point
// at the call site that actually relied on the default.
let defaultClient: AuthClient | undefined;

function getDefaultClient(): AuthClient {
  defaultClient ??= createAuthClient({
    serviceUrl: process.env.AUTH_SERVICE_URL || "",
    issuer: process.env.AUTH_ISSUER,
    clientId: process.env.AUTH_CLIENT_ID || "",
    clientSecret: process.env.AUTH_CLIENT_SECRET || "",
    redirectUri: process.env.AUTH_REDIRECT_URI,
  });
  return defaultClient;
}

export const authClient = new Proxy({} as AuthClient, {
  get(_target, prop) {
    return getDefaultClient()[prop as keyof AuthClient];
  },
});

export const requireAuth: AuthClient["requireAuth"] = (req, res, next) =>
  getDefaultClient().requireAuth(req, res, next);

// ─── Express Middleware ───────────────────────────────────────────

/**
 * Map a verification error into a response that is honest about what
 * failed. A transport failure, a platform 5xx or a 429 is an
 * availability problem: answer 503, not 401. A 4xx from the verify
 * endpoint itself is an unexpected request level failure: answer 502.
 * Never 401, which would misreport an outage as a bad credential.
 */
function respondPlatformUnavailable(res: Response, err: unknown): void {
  if (err instanceof AuthApiError && err.status >= 400 && err.status < 500 && err.status !== 429) {
    res.status(502).json({ error: "Identity platform rejected the verification request" });
    return;
  }
  res.status(503).json({ error: "Identity platform unavailable" });
}

/**
 * Middleware: require a specific permission (use after requireAuth)
 *
 * Usage: router.delete("/users/:id", requireAuth, requirePermission("users:delete"), handler)
 */
export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    // Works for any principal kind: users carry role permissions,
    // machine principals carry scopes or resolved role permissions
    const perms = req.user?.permissions ?? req.principal?.permissions;
    if (!perms) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    const [resource] = permission.split(":");

    if (perms.includes("*") || perms.includes(permission) || perms.includes(`${resource}:*`)) {
      return next();
    }

    res.status(403).json({ error: `Missing permission: ${permission}` });
  };
}
