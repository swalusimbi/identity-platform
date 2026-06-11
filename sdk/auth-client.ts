/**
 * Auth Service Client SDK
 *
 * Drop this file into any of your apps
 * to integrate with your auth service deployment
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
 *   // OAuth login redirect
 *   router.get("/login/google", (req, res) => {
 *     res.redirect(auth.getOAuthUrl("google"));
 *   });
 *
 *   // OAuth callback
 *   router.get("/auth/callback", async (req, res) => {
 *     const tokens = await auth.exchangeOAuthCode(String(req.query.code));
 *     // Set cookies, redirect to dashboard, etc.
 *   });
 *
 * A default instance configured from env vars (AUTH_SERVICE_URL,
 * AUTH_ISSUER, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, AUTH_REDIRECT_URI)
 * is exported as `authClient` with its `requireAuth` middleware.
 */

import { Request, Response, NextFunction } from "express";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

// ─── Configuration ────────────────────────────────────────────────

export interface AuthClientConfig {
  serviceUrl: string;    // https://auth.example.com
  issuer?: string;       // defaults to the serviceUrl hostname
  clientId: string;      // cl_... from when you registered this app
  clientSecret: string;  // cs_... (keep server-side only)
  redirectUri?: string;  // https://app.example.com/auth/callback
}

// ─── Types ────────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  clientId: string;
  email: string;
  permissions: string[];
}

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
  authorized: boolean;
  user?: AuthUser;
  apiKey?: {
    clientId: string;
    name: string;
    scopes: string[];
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
    interface Request {
      user?: AuthUser;
    }
  }
}

// ─── Factory ──────────────────────────────────────────────────────

export type AuthClient = ReturnType<typeof createAuthClient>;

export function createAuthClient(config: AuthClientConfig) {
  const issuer = config.issuer ?? new URL(config.serviceUrl).hostname;

  // Keys are fetched lazily on first verification, then cached in-process
  const jwks = createRemoteJWKSet(
    new URL(`${config.serviceUrl}/.well-known/jwks.json`),
    {
      cacheMaxAge: 5 * 60 * 1000,
      cooldownDuration: 30 * 1000,
    }
  );

  async function post<T>(path: string, body: unknown, errorLabel: string): Promise<T> {
    const res = await fetch(`${config.serviceUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: errorLabel }));
      throw new Error((err as { error?: string }).error || `${errorLabel}: ${res.status}`);
    }

    return res.json() as Promise<T>;
  }

  function clientCredentials() {
    return { clientId: config.clientId, clientSecret: config.clientSecret };
  }

  /**
   * Verify a JWT locally using the auth service JWKS endpoint.
   * This avoids a network call to /auth/verify on every request.
   */
  async function verifyTokenLocally(token: string): Promise<AuthUser> {
    const { payload } = await jwtVerify(token, jwks, { issuer });

    const authPayload = payload as AuthJwtPayload;
    return {
      id: authPayload.sub,
      clientId: authPayload.cid,
      email: authPayload.email,
      permissions: authPayload.permissions || [],
    };
  }

  /**
   * Verify a JWT or API key with the auth service.
   *
   * Prefer verifyTokenLocally() for normal Bearer JWT requests.
   * Use this for API keys, legacy HS256 tokens, or explicit fallback.
   */
  async function verifyTokenRemote(
    token: string,
    requiredPermission?: string
  ): Promise<VerifyResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, requiredPermission }),
    });

    return res.json() as Promise<VerifyResponse>;
  }

  return {
    config,

    verifyTokenLocally,
    verifyTokenRemote,

    /**
     * Build the OAuth redirect URL for a provider
     * Redirect the user's browser to this URL to start OAuth
     */
    getOAuthUrl(provider: "google" | "github"): string {
      if (!config.redirectUri) {
        throw new Error("redirectUri is required for OAuth flows");
      }
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
      });
      return `${config.serviceUrl}/auth/oauth/${provider}?${params}`;
    },

    /**
     * Exchange an OAuth authorization code for tokens
     * Call this from your /auth/callback route handler
     */
    exchangeOAuthCode(code: string): Promise<TokenResponse> {
      return post("/auth/oauth/token", {
        code,
        redirectUri: config.redirectUri,
        ...clientCredentials(),
      }, "Token exchange failed");
    },

    /**
     * Verify an API key with the auth service.
     * API keys are opaque and cannot be verified through JWKS.
     */
    async verifyApiKey(apiKey: string, requiredPermission?: string): Promise<VerifyResponse> {
      const res = await fetch(`${config.serviceUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey, requiredPermission }),
      });
      return res.json() as Promise<VerifyResponse>;
    },

    /**
     * Refresh an access token using a refresh token
     */
    refreshToken(refreshToken: string): Promise<RefreshResponse> {
      return post("/auth/refresh", {
        refreshToken,
        ...clientCredentials(),
      }, "Refresh failed");
    },

    /**
     * Register a new user (email/password)
     */
    register(email: string, password: string): Promise<TokenResponse> {
      return post("/auth/register", {
        email,
        password,
        ...clientCredentials(),
      }, "Registration failed");
    },

    /**
     * Login with email/password
     */
    login(email: string, password: string): Promise<TokenResponse> {
      return post("/auth/login", {
        email,
        password,
        ...clientCredentials(),
      }, "Login failed");
    },

    /**
     * Request a password reset email. resetPageUrl is the page in your
     * app that reads the token from the query string. Always resolves,
     * the service never reveals whether the email exists.
     */
    async forgotPassword(email: string, resetPageUrl: string): Promise<void> {
      await post("/auth/password/forgot", {
        email,
        url: resetPageUrl,
        ...clientCredentials(),
      }, "Password reset request failed");
    },

    /**
     * Complete a password reset with the token from the email link.
     * All of the user's sessions are revoked.
     */
    async resetPassword(token: string, newPassword: string): Promise<void> {
      await post("/auth/password/reset", {
        token,
        newPassword,
        ...clientCredentials(),
      }, "Password reset failed");
    },

    /**
     * Change the password of the logged in user. Revokes all sessions,
     * log in again afterwards.
     */
    async changePassword(
      accessToken: string,
      currentPassword: string,
      newPassword: string
    ): Promise<void> {
      const res = await fetch(`${config.serviceUrl}/auth/password/change`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Password change failed" }));
        throw new Error((err as { error?: string }).error || `Password change failed: ${res.status}`);
      }
    },

    /**
     * Send an email verification link. verifyPageUrl is the page in
     * your app that reads the token from the query string.
     */
    async sendEmailVerification(email: string, verifyPageUrl: string): Promise<void> {
      await post("/auth/email/send-verification", {
        email,
        url: verifyPageUrl,
        ...clientCredentials(),
      }, "Verification request failed");
    },

    /**
     * Confirm an email with the token from the verification link
     */
    async verifyEmail(token: string): Promise<void> {
      await post("/auth/email/verify", {
        token,
        ...clientCredentials(),
      }, "Email verification failed");
    },

    /**
     * Logout (revoke refresh token)
     */
    async logout(refreshToken: string): Promise<void> {
      await fetch(`${config.serviceUrl}/auth/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken, ...clientCredentials() }),
      });
    },

    /**
     * Middleware: require a valid access token
     *
     * Extracts Bearer token from Authorization header,
     * verifies the JWT locally via JWKS, populates req.user
     */
    requireAuth: async (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({ error: "Missing authorization header" });
        return;
      }

      const token = authHeader.split(" ")[1];

      try {
        req.user = await verifyTokenLocally(token);
        next();
      } catch {
        try {
          // Fallback for legacy HS256 tokens or temporary JWKS refresh failures.
          const result = await verifyTokenRemote(token);

          if (!result.valid || !result.user) {
            res.status(401).json({ error: result.error || "Invalid token" });
            return;
          }

          req.user = result.user;
          next();
        } catch {
          res.status(502).json({ error: "Auth service unavailable" });
        }
      }
    },
  };
}

// ─── Default instance from env ────────────────────────────────────

export const authClient = createAuthClient({
  serviceUrl: process.env.AUTH_SERVICE_URL || "https://auth.example.com",
  issuer: process.env.AUTH_ISSUER,
  clientId: process.env.AUTH_CLIENT_ID || "",
  clientSecret: process.env.AUTH_CLIENT_SECRET || "",
  redirectUri: process.env.AUTH_REDIRECT_URI,
});

export const requireAuth = authClient.requireAuth;

// ─── Express Middleware ───────────────────────────────────────────

/**
 * Middleware: require a specific permission (use after requireAuth)
 *
 * Usage: router.delete("/users/:id", requireAuth, requirePermission("users:delete"), handler)
 */
export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    const perms = req.user.permissions || [];
    const [resource] = permission.split(":");

    if (perms.includes("*") || perms.includes(permission) || perms.includes(`${resource}:*`)) {
      return next();
    }

    res.status(403).json({ error: `Missing permission: ${permission}` });
  };
}
