/**
 * Compile-only fixture (not a .test.ts, the runner ignores it).
 *
 * FUP-08: the SDK integration tests import platform internals and so
 * cannot be typechecked alongside the SDK without a Request.user
 * augmentation collision that only exists in this monorepo. A real
 * consumer imports ONLY the SDK, which is what this file does. It
 * exercises the whole documented surface so `npm run typecheck` proves
 * consumer-facing TypeScript compiles. It is never executed.
 */
import express from "express";
import {
  createAuthClient,
  requirePermission,
  AuthApiError,
  AuthTransportError,
  type AuthClient,
  type Principal,
  type MachinePrincipal,
  type VerifyResponse,
} from "../sdk/auth-client";

const auth: AuthClient = createAuthClient({
  serviceUrl: "https://iam.example.com/",
  clientId: process.env.AUTH_CLIENT_ID!,
  clientSecret: process.env.AUTH_CLIENT_SECRET,
  redirectUri: "https://app.example.com/auth/callback",
  requestTimeoutMs: 8000,
  allowLegacyHs256: false,
});

const app = express();

// User middleware and req.user typing
app.get("/dashboard", auth.requireAuth, (req, res) => {
  const email: string = req.user!.email;
  res.json({ email });
});

// Machine middleware and req.principal typing
app.post("/reports", auth.requireApiKey, requirePermission("reports:write"), (req, res) => {
  const p = req.principal as MachinePrincipal;
  res.json({ name: p.name, perms: p.permissions });
});

// Either principal on one route
app.get("/notes", auth.requirePrincipal, requirePermission("notes:read"), (req, res) => {
  const principal: Principal | undefined = req.principal;
  res.json({ kind: principal?.kind });
});

// The full call surface, with per-call options where supported
async function exercise(): Promise<void> {
  const controller = new AbortController();

  await auth.register("a@example.com", "password-123", { signal: controller.signal });
  const session = await auth.login("a@example.com", "password-123");
  const opId = auth.createRefreshOperationId();
  await auth.refreshToken(session.refreshToken, opId, { signal: controller.signal });
  await auth.logout(session.refreshToken);

  await auth.forgotPassword("a@example.com");
  await auth.resetPassword("tok", "new-password-123");
  await auth.changePassword(session.accessToken, "old", "new-password-123");
  await auth.sendEmailVerification("a@example.com");
  await auth.verifyEmail("tok");

  const state = auth.createOAuthState();
  const { verifier, challenge } = auth.createPkcePair();
  const url: string = auth.getOAuthUrl("google", { codeChallenge: challenge, state });
  void url;
  await auth.exchangeOAuthCode("code", { codeVerifier: verifier });

  const local = await auth.verifyTokenLocally(session.accessToken);
  void (local.permissions as string[]);
  const remote: VerifyResponse = await auth.verifyTokenRemote(session.accessToken, "users:read");
  void remote.authorized;
  await auth.verifyApiKey("sk_x", "users:read");
}

// Typed error handling as the guide documents it
function handle(err: unknown): void {
  if (err instanceof AuthApiError) {
    void (err.status + (err.code ?? "") );
    void err.details;
    void err.rateLimit?.resetAt;
  } else if (err instanceof AuthTransportError) {
    void err.message;
  }
}

void exercise;
void handle;
void app;
