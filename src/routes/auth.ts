import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, refreshTokens } from "../db/schema";
import { eq, and } from "drizzle-orm";
import { hashPassword, verifyPassword } from "../services/password";
import { hashToken } from "../services/token";
import {
  verifyClientCredentials,
  assignDefaultRoles,
  issueSession,
} from "../services/session";
import { AppError } from "../utils/errors";
import { audit } from "../services/audit";
import {
  strictLimiter,
  loginIpLimiter,
  loginAccountLimiter,
} from "../middleware/rateLimit";

const router = Router();

// ─── Validation schemas ───────────────────────────────────────────

const registerSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(8).max(128),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  clientId: z.string(),
  clientSecret: z.string().min(1).optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

// ─── POST /auth/register ──────────────────────────────────────────

router.post("/register", strictLimiter, async (req: Request, res: Response) => {
  const body = registerSchema.parse(req.body);

  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

  if (!client.allowUserRegistration) {
    throw AppError.forbidden(
      "Registration is disabled for this client",
      "REGISTRATION_DISABLED"
    );
  }

  // Check for existing user under this client
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(
      and(eq(users.clientId, client.id), eq(users.email, body.email.toLowerCase()))
    )
    .limit(1);

  if (existing) throw AppError.conflict("Email already registered", "EMAIL_EXISTS");

  // Create user
  const passwordHash = await hashPassword(body.password);
  const [user] = await db
    .insert(users)
    .values({
      clientId: client.id,
      email: body.email.toLowerCase(),
      passwordHash,
    })
    .returning({ id: users.id, email: users.email });

  await assignDefaultRoles(user.id, client.id);

  const session = await issueSession(user, client.id, req);

  await audit(req, {
    clientId: client.id,
    action: "user.registered",
    actorType: "user",
    actorId: user.id,
    details: { method: "password" },
  });

  res.status(201).json({
    user: { id: user.id, email: user.email },
    ...session,
  });
});

// ─── POST /auth/login ─────────────────────────────────────────────

router.post("/login", loginIpLimiter, loginAccountLimiter, async (req: Request, res: Response) => {
  const body = loginSchema.parse(req.body);

  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

  // Find user
  const [user] = await db
    .select()
    .from(users)
    .where(
      and(
        eq(users.clientId, client.id),
        eq(users.email, body.email.toLowerCase()),
        eq(users.isActive, true)
      )
    )
    .limit(1);

  // Constant-time: always hash even if user doesn't exist (timing attack prevention)
  if (!user || !user.passwordHash) {
    await hashPassword("dummy-password-for-timing");
    await audit(req, {
      clientId: client.id,
      action: "user.login_failed",
      actorType: "anonymous",
      details: { email: body.email.toLowerCase() },
    });
    throw AppError.unauthorized("Invalid credentials", "INVALID_CREDENTIALS");
  }

  const valid = await verifyPassword(user.passwordHash, body.password);
  if (!valid) {
    await audit(req, {
      clientId: client.id,
      action: "user.login_failed",
      actorType: "anonymous",
      details: { email: body.email.toLowerCase() },
    });
    throw AppError.unauthorized("Invalid credentials", "INVALID_CREDENTIALS");
  }

  const session = await issueSession(user, client.id, req);

  await audit(req, {
    clientId: client.id,
    action: "user.login",
    actorType: "user",
    actorId: user.id,
    details: { method: "password" },
  });

  res.json({
    user: { id: user.id, email: user.email },
    ...session,
  });
});

// ─── POST /auth/refresh ───────────────────────────────────────────

router.post("/refresh", async (req: Request, res: Response) => {
  const {
    refreshToken: rawToken,
    clientId,
    clientSecret,
  } = refreshSchema.parse(req.body);
  const client = await verifyClientCredentials(clientId, clientSecret);
  const tokenHash = hashToken(rawToken);

  // Find and validate the stored refresh token
  const [stored] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.tokenHash, tokenHash))
    .limit(1);

  const [owner] = stored
    ? await db
        .select()
        .from(users)
        .where(and(eq(users.id, stored.userId), eq(users.clientId, client.id)))
        .limit(1)
    : [];

  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    // A rotated token coming back means two parties held the same
    // token: replay. Revoke ALL of the user's tokens as a precaution.
    // Tokens revoked by logout or the sessions API answer a plain 401,
    // the revoked device retrying is expected, not theft.
    if (
      owner &&
      stored.revoked &&
      (stored.revokedReason ?? "rotated") === "rotated"
    ) {
      await db
        .update(refreshTokens)
        .set({ revoked: true, revokedReason: "security" })
        .where(
          and(eq(refreshTokens.userId, stored.userId), eq(refreshTokens.revoked, false))
        );
      await audit(req, {
        clientId: client.id,
        action: "session.replay_detected",
        actorType: "user",
        actorId: stored.userId,
      });
    }
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  if (!owner || !owner.isActive) {
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  // Rotate only after confirming the refresh token belongs to this client.
  await db
    .update(refreshTokens)
    .set({ revoked: true, revokedReason: "rotated" })
    .where(eq(refreshTokens.id, stored.id));

  const session = await issueSession(owner, owner.clientId, req);

  res.json(session);
});

// ─── POST /auth/logout ────────────────────────────────────────────

router.post("/logout", async (req: Request, res: Response) => {
  const {
    refreshToken: rawToken,
    clientId,
    clientSecret,
  } = refreshSchema.parse(req.body);
  const client = await verifyClientCredentials(clientId, clientSecret);
  const tokenHash = hashToken(rawToken);

  const [stored] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.tokenHash, tokenHash))
    .limit(1);

  if (stored) {
    const [user] = await db
      .select({ clientId: users.clientId })
      .from(users)
      .where(eq(users.id, stored.userId))
      .limit(1);

    if (user?.clientId === client.id) {
      await db
        .update(refreshTokens)
        .set({ revoked: true, revokedReason: "logout" })
        .where(eq(refreshTokens.id, stored.id));
      await audit(req, {
        clientId: client.id,
        action: "user.logout",
        actorType: "user",
        actorId: stored.userId,
      });
    }
  }

  res.json({ message: "Logged out" });
});

export default router;
