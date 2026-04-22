/**
 * Auth Service Client SDK
 *
 * Drop this file into any of your apps (My App, My Tools, etc.)
 * to integrate with auth.example.com
 *
 * Required dependency:
 *   npm install jose
 *
 * Usage:
 *   import { authClient, requireAuth, requirePermission } from "./lib/auth";
 *
 *   // Protect a route
 *   router.get("/dashboard", requireAuth, (req, res) => {
 *     console.log(req.user); // { id, clientId, email, permissions }
 *   });
 *
 *   // Require specific permission
 *   router.delete("/users/:id", requireAuth, requirePermission("users:delete"), handler);
 *
 *   // OAuth login redirect
 *   router.get("/login/google", (req, res) => {
 *     res.redirect(authClient.getOAuthUrl("google"));
 *   });
 *
 *   // OAuth callback
 *   router.get("/auth/callback", async (req, res) => {
 *     const tokens = await authClient.exchangeOAuthCode(req.query.code);
 *     // Set cookies, redirect to dashboard, etc.
 *   });
 */

import { Request, Response, NextFunction } from "express";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

// ─── Configuration ────────────────────────────────────────────────

interface AuthClientConfig {
  serviceUrl: string;    // https://auth.example.com
  issuer: string;        // auth.example.com
  clientId: string;      // cl_... from when you registered this app
  clientSecret: string;  // cs_... (keep server-side only)
  redirectUri: string;   // https://yourapp.com/auth/callback
}

const config: AuthClientConfig = {
  serviceUrl: process.env.AUTH_SERVICE_URL || "https://auth.example.com",
  issuer: process.env.AUTH_ISSUER || "auth.example.com",
  clientId: process.env.AUTH_CLIENT_ID || "",
  clientSecret: process.env.AUTH_CLIENT_SECRET || "",
  redirectUri: process.env.AUTH_REDIRECT_URI || "",
};

const jwks = createRemoteJWKSet(
  new URL(`${config.serviceUrl}/.well-known/jwks.json`),
  {
    cacheMaxAge: 5 * 60 * 1000,
    cooldownDuration: 30 * 1000,
  }
);

// ─── Types ────────────────────────────────────────────────────────

interface AuthUser {
  id: string;
  clientId: string;
  email: string;
  permissions: string[];
}

interface TokenResponse {
  user: { id: string; email: string };
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface VerifyResponse {
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

// ─── Auth Client ──────────────────────────────────────────────────

export const authClient = {
  /**
   * Build the OAuth redirect URL for a provider
   * Redirect the user's browser to this URL to start OAuth
   */
  getOAuthUrl(provider: "google" | "github"): string {
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
  async exchangeOAuthCode(code: string): Promise<TokenResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.redirectUri,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Token exchange failed" }));
      throw new Error(err.error || `Auth service returned ${res.status}`);
    }

    return res.json();
  },

  /**
   * Verify a JWT locally using the auth service JWKS endpoint.
   * This avoids a network call to /auth/verify on every request.
   *
   * The JWKS client caches public keys in-process. It only calls
   * /.well-known/jwks.json when the cache is cold or needs refresh.
   */
  async verifyTokenLocally(token: string): Promise<AuthUser> {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: config.issuer,
    });

    const authPayload = payload as AuthJwtPayload;
    return {
      id: authPayload.sub,
      clientId: authPayload.cid,
      email: authPayload.email,
      permissions: authPayload.permissions || [],
    };
  },

  /**
   * Verify a JWT or API key with the auth service.
   *
   * Prefer verifyTokenLocally() for normal Bearer JWT requests.
   * Use this for API keys, legacy HS256 tokens, or explicit fallback.
   */
  async verifyTokenRemote(token: string, requiredPermission?: string): Promise<VerifyResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, requiredPermission }),
    });

    return res.json();
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

    return res.json();
  },

  /**
   * Refresh an access token using a refresh token
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Refresh failed" }));
      throw new Error(err.error || `Refresh returned ${res.status}`);
    }

    return res.json();
  },

  /**
   * Register a new user (email/password)
   */
  async register(email: string, password: string): Promise<TokenResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, clientId: config.clientId }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Registration failed" }));
      throw new Error(err.error || `Register returned ${res.status}`);
    }

    return res.json();
  },

  /**
   * Login with email/password
   */
  async login(email: string, password: string): Promise<TokenResponse> {
    const res = await fetch(`${config.serviceUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, clientId: config.clientId }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Login failed" }));
      throw new Error(err.error || `Login returned ${res.status}`);
    }

    return res.json();
  },

  /**
   * Logout (revoke refresh token)
   */
  async logout(refreshToken: string): Promise<void> {
    await fetch(`${config.serviceUrl}/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
  },
};

// ─── Express Middleware ───────────────────────────────────────────

/**
 * Middleware: require a valid access token
 *
 * Extracts Bearer token from Authorization header,
 * verifies the JWT locally via JWKS, populates req.user
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing authorization header" });
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    req.user = await authClient.verifyTokenLocally(token);
    next();
  } catch {
    try {
      // Fallback for legacy HS256 tokens or temporary JWKS refresh failures.
      const result = await authClient.verifyTokenRemote(token);

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
}

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
