import {
  SignJWT,
  jwtVerify,
  JWTPayload,
  importPKCS8,
  importSPKI,
  exportJWK,
  decodeProtectedHeader,
  JWK,
  KeyLike,
} from "jose";
import { randomBytes, createHash } from "crypto";
import { env } from "../utils/env";

const legacySecret = new TextEncoder().encode(env.JWT_SECRET);
const JWT_ALG = "EdDSA";

let privateKeyPromise: Promise<KeyLike> | undefined;
let publicKeyPromise: Promise<KeyLike> | undefined;
let publicJwkPromise: Promise<JWK> | undefined;

function normalizePem(value: string): string {
  return value.replace(/\\n/g, "\n").trim();
}

function hasAsymmetricJwtKeys(): boolean {
  return Boolean(env.JWT_PRIVATE_KEY && env.JWT_PUBLIC_KEY);
}

function getPrivateKey(): Promise<KeyLike> {
  if (!env.JWT_PRIVATE_KEY) {
    throw new Error("JWT_PRIVATE_KEY is required for asymmetric JWT signing");
  }

  privateKeyPromise ??= importPKCS8(normalizePem(env.JWT_PRIVATE_KEY), JWT_ALG);
  return privateKeyPromise;
}

function getPublicKey(): Promise<KeyLike> {
  if (!env.JWT_PUBLIC_KEY) {
    throw new Error("JWT_PUBLIC_KEY is required for asymmetric JWT verification");
  }

  publicKeyPromise ??= importSPKI(normalizePem(env.JWT_PUBLIC_KEY), JWT_ALG);
  return publicKeyPromise;
}

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
 * Return the public JWK used by consuming apps for local JWT verification.
 */
export async function getPublicJwk(): Promise<JWK> {
  if (!hasAsymmetricJwtKeys()) {
    throw new Error("JWKS is unavailable until JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are configured");
  }

  publicJwkPromise ??= getPublicKey().then(async (key) => {
    const jwk = await exportJWK(key);
    return {
      ...jwk,
      kid: env.JWT_KEY_ID,
      alg: JWT_ALG,
      use: "sig",
    };
  });

  return publicJwkPromise;
}

/**
 * Sign a short-lived access token (JWT)
 * Contains user ID, client ID, email, and flattened permissions
 */
export async function signAccessToken(
  payload: Omit<TokenPayload, "iat" | "exp" | "iss">
): Promise<string> {
  if (hasAsymmetricJwtKeys()) {
    const privateKey = await getPrivateKey();
    return new SignJWT({ ...payload })
      .setProtectedHeader({ alg: JWT_ALG, kid: env.JWT_KEY_ID })
      .setIssuedAt()
      .setIssuer("auth.example.com")
      .setExpirationTime(env.JWT_ACCESS_EXPIRY)
      .sign(privateKey);
  }

  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256", kid: "legacy-hs256" })
    .setIssuedAt()
    .setIssuer("auth.example.com")
    .setExpirationTime(env.JWT_ACCESS_EXPIRY)
    .sign(legacySecret);
}

/**
 * Verify and decode an access token
 */
export async function verifyAccessToken(
  token: string
): Promise<TokenPayload> {
  const options = { issuer: "auth.example.com" };
  const { alg } = decodeProtectedHeader(token);

  if (alg === "HS256") {
    const { payload } = await jwtVerify(token, legacySecret, options);
    return payload as TokenPayload;
  }

  const key = hasAsymmetricJwtKeys() ? await getPublicKey() : legacySecret;
  const { payload } = await jwtVerify(token, key, options);
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
