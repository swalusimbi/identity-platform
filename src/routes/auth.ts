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
import { strictLimiter } from "../middleware/rateLimit";

const router = Router();

// ─── Validation schemas ───────────────────────────────────────────

const registerSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(8).max(128),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  clientId: z.string(),
  clientSecret: z.string().min(1),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
});

// ─── POST /auth/register ──────────────────────────────────────────

router.post("/register", strictLimiter, async (req: Request, res: Response) => {
  const body = registerSchema.parse(req.body);

  const client = await verifyClientCredentials(body.clientId, body.clientSecret);

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

  res.status(201).json({
    user: { id: user.id, email: user.email },
    ...session,
  });
});

// ─── POST /auth/login ─────────────────────────────────────────────

router.post("/login", strictLimiter, async (req: Request, res: Response) => {
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
    throw AppError.unauthorized("Invalid credentials", "INVALID_CREDENTIALS");
  }

  const valid = await verifyPassword(user.passwordHash, body.password);
  if (!valid) throw AppError.unauthorized("Invalid credentials", "INVALID_CREDENTIALS");

  const session = await issueSession(user, client.id, req);

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

  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    // If token was already used (revoked), this might be a replay attack
    // Revoke ALL tokens for this user as a precaution
    if (stored?.revoked) {
      await db
        .update(refreshTokens)
        .set({ revoked: true })
        .where(eq(refreshTokens.userId, stored.userId));
    }
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  // Load user + permissions
  const [user] = await db
    .select()
    .from(users)
    .where(and(eq(users.id, stored.userId), eq(users.isActive, true)))
    .limit(1);

  if (!user || user.clientId !== client.id) {
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  // Rotate only after confirming the refresh token belongs to this client.
  await db
    .update(refreshTokens)
    .set({ revoked: true })
    .where(eq(refreshTokens.id, stored.id));

  const session = await issueSession(user, user.clientId, req);

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
        .set({ revoked: true })
        .where(eq(refreshTokens.id, stored.id));
    }
  }

  res.json({ message: "Logged out" });
});

export default router;
