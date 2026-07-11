import {
  randomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from "crypto";
import { env } from "../utils/env";
import { redis } from "../db/redis";
import { AppError } from "../utils/errors";

// ─── Provider configs ─────────────────────────────────────────────

interface OAuthProviderConfig {
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
}

export function getProviderConfig(provider: string): OAuthProviderConfig {
  switch (provider) {
    case "google":
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
        throw AppError.badRequest("Google OAuth is not enabled", "PROVIDER_DISABLED");
      }
      return {
        authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        userInfoUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        scopes: ["openid", "email", "profile"],
      };

    case "github":
      if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
        throw AppError.badRequest("GitHub OAuth is not enabled", "PROVIDER_DISABLED");
      }
      return {
        authUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
        userInfoUrl: "https://api.github.com/user",
        clientId: env.GITHUB_CLIENT_ID,
        clientSecret: env.GITHUB_CLIENT_SECRET,
        scopes: ["user:email"],
      };

    default:
      throw AppError.badRequest(
        `Unsupported provider: ${provider}`,
        "UNSUPPORTED_PROVIDER"
      );
  }
}

// ─── State parameter (encrypts client_id + redirect_uri) ──────────

const STATE_ALGORITHM = "aes-256-gcm";
// Derive a 32-byte key from JWT_SECRET for state encryption
const stateKey = createHash("sha256").update(env.JWT_SECRET).digest();
// A state older than this is rejected, the user must restart the flow
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

interface OAuthState {
  clientId: string;
  redirectUri: string;
  // Which provider this transaction was started for. The callback
  // refuses a state presented to a different provider's endpoint.
  provider?: string;
  nonce: string; // Replay protection, consumed once by the callback
  codeChallenge?: string; // PKCE S256 challenge
  // The consumer application's own one-time value, opaque to the
  // platform, echoed back on the callback redirect so the consumer
  // can bind the response to the browser session that started it
  consumerState?: string;
  iat?: number; // Set by encryptState, checked by decryptState
}

export function encryptState(state: OAuthState): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(STATE_ALGORITHM, stateKey, iv);

  const payload = JSON.stringify({ ...state, iat: Date.now() });
  let encrypted = cipher.update(payload, "utf8", "base64url");
  encrypted += cipher.final("base64url");

  const tag = cipher.getAuthTag();

  // Pack: iv.tag.ciphertext
  return `${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted}`;
}

export function decryptState(stateParam: string): OAuthState {
  const parts = stateParam.split(".");
  if (parts.length !== 3) throw new Error("Invalid state parameter");

  const [ivB64, tagB64, ciphertext] = parts;
  const iv = Buffer.from(ivB64, "base64url");
  const tag = Buffer.from(tagB64, "base64url");

  const decipher = createDecipheriv(STATE_ALGORITHM, stateKey, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(ciphertext, "base64url", "utf8");
  decrypted += decipher.final("utf8");

  const state: OAuthState = JSON.parse(decrypted);
  if (!state.iat || Date.now() - state.iat > STATE_MAX_AGE_MS) {
    throw new Error("State parameter expired");
  }

  return state;
}

const STATE_NONCE_PREFIX = "oauth:state:";

/**
 * Consume a state nonce, making every platform state single use. The
 * marker lives exactly as long as an unconsumed state could still be
 * valid. Fails closed when Redis is down, like authorization codes.
 */
export async function consumeStateNonce(nonce: string): Promise<boolean> {
  const result = await redis.set(
    `${STATE_NONCE_PREFIX}${nonce}`,
    "1",
    "EX",
    Math.ceil(STATE_MAX_AGE_MS / 1000),
    "NX"
  );
  return result === "OK";
}

// ─── Authorization code (short-lived, stored in Redis) ────────────

const CODE_TTL = 60; // 60 seconds
const CODE_PREFIX = "oauth:code:";
const CONSUME_AUTH_CODE_SCRIPT = `
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
redis.call("DEL", KEYS[1])
return value
`;

interface AuthCodeData {
  userId: string;
  clientId: string; // Internal UUID
  appClientId: string; // The cl_... string
  redirectUri: string;
  codeChallenge?: string; // PKCE S256 challenge, verifier required when set
}

export function generateAuthCode(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * PKCE S256 check (RFC 7636): base64url(sha256(verifier)) == challenge
 */
export function verifierMatchesChallenge(
  verifier: string,
  challenge: string
): boolean {
  const computed = createHash("sha256").update(verifier).digest("base64url");
  if (computed.length !== challenge.length) return false;
  return timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
}

export async function storeAuthCode(
  code: string,
  data: AuthCodeData
): Promise<void> {
  const hash = createHash("sha256").update(code).digest("hex");
  await redis.setex(`${CODE_PREFIX}${hash}`, CODE_TTL, JSON.stringify(data));
}

export async function consumeAuthCode(
  code: string
): Promise<AuthCodeData | null> {
  const hash = createHash("sha256").update(code).digest("hex");
  const key = `${CODE_PREFIX}${hash}`;

  const data = await redis.eval(
    CONSUME_AUTH_CODE_SCRIPT,
    1,
    key
  ) as string | null;
  if (!data) return null;

  return JSON.parse(data);
}

export async function resolveAuthCode(
  code: string
): Promise<AuthCodeData | null> {
  const hash = createHash("sha256").update(code).digest("hex");
  const data = await redis.get(`${CODE_PREFIX}${hash}`);
  if (!data) return null;

  return JSON.parse(data);
}

// ─── Provider token + user info exchange ──────────────────────────

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  scope?: string;
}

interface OAuthUserInfo {
  email: string;
  name?: string;
  providerId: string;
}

interface GoogleUserInfoResponse {
  email: string;
  name?: string;
  id: string;
}

interface GitHubUserInfoResponse {
  email?: string | null;
  name?: string | null;
  login: string;
  id: number;
}

interface GitHubEmailResponse {
  email: string;
  primary: boolean;
  verified: boolean;
}

export async function exchangeCodeForProviderToken(
  provider: string,
  code: string,
  callbackUrl: string
): Promise<OAuthTokenResponse> {
  const config = getProviderConfig(provider);

  const params = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: callbackUrl,
    grant_type: "authorization_code",
  });

  const res = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: params.toString(),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`OAuth token exchange failed: ${res.status} ${body}`);
  }

  return (await res.json()) as OAuthTokenResponse;
}

export async function fetchProviderUserInfo(
  provider: string,
  accessToken: string
): Promise<OAuthUserInfo> {
  const config = getProviderConfig(provider);

  const res = await fetch(config.userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) throw new Error(`Failed to fetch user info: ${res.status}`);

  if (provider === "google") {
    const data = (await res.json()) as GoogleUserInfoResponse;

    return {
      email: data.email,
      name: data.name,
      providerId: data.id,
    };
  }

  if (provider === "github") {
    const data = (await res.json()) as GitHubUserInfoResponse;

    // Only trust verified emails. The profile email and unverified entries
    // can be set to anyone's address, which would let an attacker link
    // their GitHub account to an existing user here.
    let email: string | undefined;
    const emailRes = await fetch("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (emailRes.ok) {
      const emails = (await emailRes.json()) as GitHubEmailResponse[];
      const primary = emails.find((e) => e.primary && e.verified);
      email = primary?.email || emails.find((e) => e.verified)?.email;
    }
    if (!email) throw new Error("GitHub account has no verified email");

    return {
      email,
      name: data.name || data.login,
      providerId: String(data.id),
    };
  }

  throw new Error(`Unsupported provider: ${provider}`);
}
