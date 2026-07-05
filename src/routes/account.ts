import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, refreshTokens } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { hashPassword, verifyPassword } from "../services/password";
import { verifyClientCredentials } from "../services/session";
import {
  createAccountToken,
  consumeAccountToken,
  AccountTokenPurpose,
} from "../services/accountToken";
import { sendMail } from "../services/mailer";
import { audit } from "../services/audit";
import { authenticate } from "../middleware/authenticate";
import { strictLimiter } from "../middleware/rateLimit";
import { AppError } from "../utils/errors";

const router = Router();

// ─── Validation schemas ───────────────────────────────────────────

const requestLinkSchema = z.object({
  email: z.string().email(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

const resetSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(8).max(128),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

const verifyEmailSchema = z.object({
  token: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(128),
});

// ─── Helpers ──────────────────────────────────────────────────────

function buildLink(base: string, token: string): string {
  const url = new URL(base);
  url.searchParams.set("token", token);
  return url.toString();
}

async function findActiveUser(clientUuid: string, email: string) {
  const [user] = await db
    .select()
    .from(users)
    .where(
      and(
        eq(users.clientId, clientUuid),
        eq(users.email, email.toLowerCase()),
        eq(users.isActive, true)
      )
    )
    .limit(1);
  return user;
}

async function revokeAllRefreshTokens(userId: string): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revoked: true })
    .where(eq(refreshTokens.userId, userId));
}

/**
 * Consume a token and resolve its user, scoped to the calling client.
 * Both failure modes return the same error so tokens can't be probed.
 */
async function consumeForClient(
  token: string,
  purpose: AccountTokenPurpose,
  clientUuid: string,
  errorCode: string
) {
  const consumed = await consumeAccountToken(token, purpose);
  if (!consumed) {
    throw AppError.unauthorized("Invalid or expired token", errorCode);
  }

  const [user] = await db
    .select()
    .from(users)
    .where(
      and(
        eq(users.id, consumed.userId),
        eq(users.clientId, clientUuid),
        eq(users.isActive, true)
      )
    )
    .limit(1);

  if (!user) {
    throw AppError.unauthorized("Invalid or expired token", errorCode);
  }

  return user;
}

// ─── POST /auth/password/forgot ───────────────────────────────────
// Always answers 200 so account existence can't be probed

router.post("/password/forgot", strictLimiter, async (req: Request, res: Response) => {
  const body = requestLinkSchema.parse(req.body);
  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

  // Config error, not an account statement, so an explicit 400 is safe
  if (!client.passwordResetUrl) {
    throw AppError.badRequest(
      "Password reset is not configured for this client",
      "RESET_URL_NOT_CONFIGURED"
    );
  }

  const user = await findActiveUser(client.id, body.email);
  if (user) {
    const token = await createAccountToken(user.id, "password_reset");
    await sendMail({
      to: user.email,
      subject: "Reset your password",
      text: [
        `A password reset was requested for your ${client.name} account.`,
        "",
        `Reset it here (valid for 1 hour): ${buildLink(client.passwordResetUrl, token)}`,
        "",
        "If you did not request this, you can ignore this email.",
      ].join("\n"),
    });
  }

  await audit(req, {
    clientId: client.id,
    action: "password.reset_requested",
    actorType: "anonymous",
    details: { email: body.email.toLowerCase() },
  });

  res.json({ message: "If that email is registered, a reset link has been sent" });
});

// ─── POST /auth/password/reset ────────────────────────────────────

router.post("/password/reset", strictLimiter, async (req: Request, res: Response) => {
  const body = resetSchema.parse(req.body);
  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

  const user = await consumeForClient(
    body.token,
    "password_reset",
    client.id,
    "INVALID_RESET_TOKEN"
  );

  const passwordHash = await hashPassword(body.newPassword);
  await db
    .update(users)
    .set({
      passwordHash,
      // Completing a reset proves control of the mailbox
      emailVerified: true,
      updatedAt: new Date(),
    })
    .where(eq(users.id, user.id));

  // A reset usually means the old credentials can't be trusted
  await revokeAllRefreshTokens(user.id);

  await audit(req, {
    clientId: client.id,
    action: "password.reset_completed",
    actorType: "user",
    actorId: user.id,
  });

  res.json({ message: "Password reset" });
});

// ─── POST /auth/email/send-verification ───────────────────────────
// Always answers 200, mirrors the forgot endpoint

router.post(
  "/email/send-verification",
  strictLimiter,
  async (req: Request, res: Response) => {
    const body = requestLinkSchema.parse(req.body);
    const client = await verifyClientCredentials(body.clientId, body.clientSecret);

    if (!client.emailVerifyUrl) {
      throw AppError.badRequest(
        "Email verification is not configured for this client",
        "VERIFY_URL_NOT_CONFIGURED"
      );
    }

    const user = await findActiveUser(client.id, body.email);
    if (user && !user.emailVerified) {
      const token = await createAccountToken(user.id, "email_verify");
      await sendMail({
        to: user.email,
        subject: "Verify your email",
        text: [
          `Confirm the email for your ${client.name} account.`,
          "",
          `Verify it here (valid for 24 hours): ${buildLink(client.emailVerifyUrl, token)}`,
        ].join("\n"),
      });
    }

    res.json({ message: "If that email is registered, a verification link has been sent" });
  }
);

// ─── POST /auth/email/verify ──────────────────────────────────────

router.post("/email/verify", async (req: Request, res: Response) => {
  const body = verifyEmailSchema.parse(req.body);
  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

  const user = await consumeForClient(
    body.token,
    "email_verify",
    client.id,
    "INVALID_VERIFY_TOKEN"
  );

  await db
    .update(users)
    .set({ emailVerified: true, updatedAt: new Date() })
    .where(eq(users.id, user.id));

  await audit(req, {
    clientId: client.id,
    action: "email.verified",
    actorType: "user",
    actorId: user.id,
  });

  res.json({ message: "Email verified" });
});

// ─── POST /auth/password/change ───────────────────────────────────
// Authenticated with the user's own Bearer token

router.post("/password/change", authenticate, async (req: Request, res: Response) => {
  if (!req.user) {
    throw AppError.unauthorized("Bearer token required");
  }
  const body = changePasswordSchema.parse(req.body);

  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, req.user.sub), eq(users.isActive, true)))
    .limit(1);

  if (!user) throw AppError.unauthorized("User not found or inactive");
  if (!user.passwordHash) {
    throw AppError.badRequest(
      "This account has no password. Use the password reset flow to set one.",
      "PASSWORD_NOT_SET"
    );
  }

  const valid = await verifyPassword(user.passwordHash, body.currentPassword);
  if (!valid) {
    throw AppError.unauthorized("Invalid credentials", "INVALID_CREDENTIALS");
  }

  const passwordHash = await hashPassword(body.newPassword);
  await db
    .update(users)
    .set({ passwordHash, updatedAt: new Date() })
    .where(eq(users.id, user.id));

  // Sign out every session, the caller logs in again with the new password
  await revokeAllRefreshTokens(user.id);

  await audit(req, {
    clientId: user.clientId,
    action: "password.changed",
    actorType: "user",
    actorId: user.id,
  });

  res.json({ message: "Password changed" });
});

export default router;
