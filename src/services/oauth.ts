import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";
import { env } from "../utils/env";
import { redis } from "../db/redis";

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
        throw new Error("Google OAuth not configured");
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
        throw new Error("GitHub OAuth not configured");
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
      throw new Error(`Unsupported provider: ${provider}`);
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
  nonce: string; // Replay protection
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
}

export function generateAuthCode(): string {
  return randomBytes(32).toString("base64url");
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

    // GitHub might not return email in profile — fetch from emails endpoint
    let email = data.email;
    if (!email) {
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (emailRes.ok) {
        const emails = (await emailRes.json()) as GitHubEmailResponse[];
        const primary = emails.find((e) => e.primary && e.verified);
        email = primary?.email || emails[0]?.email;
      }
    }
    if (!email) throw new Error("Could not retrieve email from GitHub");

    return {
      email,
      name: data.name || data.login,
      providerId: String(data.id),
    };
  }

  throw new Error(`Unsupported provider: ${provider}`);
}
