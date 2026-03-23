import { SignJWT, jwtVerify, JWTPayload } from "jose";
import { randomBytes, createHash } from "crypto";
import { env } from "../utils/env";

// Encode secret once at startup
const secret = new TextEncoder().encode(env.JWT_SECRET);

export interface TokenPayload extends JWTPayload {
  sub: string; // user ID
  cid: string; // client ID
  email: string;
  permissions: string[]; // ["users:read", "billing:write"]
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number; // seconds
}

/**
 * Sign a short-lived access token (JWT)
 * Contains user ID, client ID, email, and flattened permissions
 */
export async function signAccessToken(
  payload: Omit<TokenPayload, "iat" | "exp" | "iss">
): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer("auth.example.com")
    .setExpirationTime(env.JWT_ACCESS_EXPIRY)
    .sign(secret);
}

/**
 * Verify and decode an access token
 */
export async function verifyAccessToken(
  token: string
): Promise<TokenPayload> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: "auth.example.com",
  });
  return payload as TokenPayload;
}

/**
 * Generate a cryptographically secure refresh token (opaque, not JWT)
 * Returns both the raw token (sent to client) and its hash (stored in DB)
 */
export function generateRefreshToken(): {
  token: string;
  hash: string;
} {
  const token = randomBytes(48).toString("base64url");
  const hash = hashToken(token);
  return { token, hash };
}

/**
 * SHA-256 hash a token for storage — we never store raw tokens
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Build a full token pair (access + refresh)
 */
export async function createTokenPair(
  payload: Omit<TokenPayload, "iat" | "exp" | "iss">
): Promise<TokenPair & { refreshTokenHash: string }> {
  const [accessToken, { token: refreshToken, hash: refreshTokenHash }] =
    await Promise.all([
      signAccessToken(payload),
      Promise.resolve(generateRefreshToken()),
    ]);

  // Parse expiry string to seconds for the response
  const expiresIn = parseExpiry(env.JWT_ACCESS_EXPIRY);

  return { accessToken, refreshToken, expiresIn, refreshTokenHash };
}

function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) return 900; // default 15 min
  const [, num, unit] = match;
  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
  };
  return parseInt(num) * (multipliers[unit] || 60);
}
