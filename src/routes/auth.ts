import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, refreshTokens } from "../db/schema";
import { eq, and, gt } from "drizzle-orm";
import { timingSafeEqual } from "crypto";
import { hashPassword, verifyPassword } from "../services/password";
import { hashToken, type TokenPair } from "../services/token";
import {
  verifyClientCredentials,
  assignDefaultRoles,
  issueSession,
  prepareSession,
} from "../services/session";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";
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

const clientTokenSchema = z.object({
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).optional(),
});

const refreshSchema = clientTokenSchema.extend({
  operationId: z.string().uuid(),
});

async function revokeSessionsForReplay(
  req: Request,
  clientId: string,
  userId: string
): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revoked: true, revokedReason: "security" })
    .where(
      and(eq(refreshTokens.userId, userId), eq(refreshTokens.revoked, false))
    );
  await audit(req, {
    clientId,
    action: "session.replay_detected",
    actorType: "user",
    actorId: userId,
  });
}

function operationHashesMatch(expected: string, actual: string): boolean {
  const expectedBuffer = Buffer.from(expected, "hex");
  const actualBuffer = Buffer.from(actual, "hex");
  return (
    expectedBuffer.length === actualBuffer.length &&
    timingSafeEqual(expectedBuffer, actualBuffer)
  );
}

async function replaceUnusedRefreshSuccessor(
  req: Request,
  client: { id: string; clientId: string },
  owner: { id: string; email: string },
  predecessorId: string,
  operationHash: string
): Promise<TokenPair | null> {
  const [candidate] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.id, predecessorId))
    .limit(1);
  const graceCutoff = new Date(
    Date.now() - env.REFRESH_RETRY_GRACE_SECONDS * 1000
  );

  if (
    !candidate?.revoked ||
    (candidate.revokedReason ?? "rotated") !== "rotated" ||
    !candidate.rotationOperationHash ||
    !operationHashesMatch(candidate.rotationOperationHash, operationHash) ||
    !candidate.rotatedAt ||
    candidate.rotatedAt < graceCutoff ||
    !candidate.replacedByTokenId
  ) {
    return null;
  }

  const prepared = await prepareSession(owner, client, req);
  const replaced = await db.transaction(async (tx) => {
    const [predecessor] = await tx
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.id, predecessorId))
      .for("update");
    const lockedGraceCutoff = new Date(
      Date.now() - env.REFRESH_RETRY_GRACE_SECONDS * 1000
    );

    if (
      !predecessor?.revoked ||
      (predecessor.revokedReason ?? "rotated") !== "rotated" ||
      !predecessor.rotationOperationHash ||
      !operationHashesMatch(predecessor.rotationOperationHash, operationHash) ||
      !predecessor.rotatedAt ||
      predecessor.rotatedAt < lockedGraceCutoff ||
      !predecessor.replacedByTokenId
    ) {
      return false;
    }

    const [successor] = await tx
      .update(refreshTokens)
      .set({ revoked: true, revokedReason: "retry" })
      .where(
        and(
          eq(refreshTokens.id, predecessor.replacedByTokenId),
          eq(refreshTokens.userId, owner.id),
          eq(refreshTokens.revoked, false),
          gt(refreshTokens.expiresAt, new Date())
        )
      )
      .returning({ id: refreshTokens.id });

    if (!successor) return false;

    await tx.insert(refreshTokens).values(prepared.refreshTokenRecord);
    await tx
      .update(refreshTokens)
      .set({ replacedByTokenId: prepared.refreshTokenRecord.id })
      .where(eq(refreshTokens.id, predecessor.id));
    return true;
  });

  return replaced ? prepared.response : null;
}

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

  const session = await issueSession(user, client, req);

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

  const session = await issueSession(user, client, req);

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
    operationId,
  } = refreshSchema.parse(req.body);
  const client = await verifyClientCredentials(clientId, clientSecret);
  const tokenHash = hashToken(rawToken);
  const operationHash = hashToken(operationId);

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
    // A matching operation may be a retry after a lost response. Other
    // rotated-token presentations retain the strict replay response.
    if (
      owner &&
      stored.revoked &&
      (stored.revokedReason ?? "rotated") === "rotated"
    ) {
      if (owner.isActive) {
        const replacement = await replaceUnusedRefreshSuccessor(
          req,
          client,
          owner,
          stored.id,
          operationHash
        );
        if (replacement) {
          res.json(replacement);
          return;
        }
      }

      await revokeSessionsForReplay(req, client.id, stored.userId);
    }
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  if (!owner || !owner.isActive) {
    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  const prepared = await prepareSession(owner, client, req);
  const now = new Date();
  const rotated = await db.transaction(async (tx) => {
    const [consumed] = await tx
      .update(refreshTokens)
      .set({
        revoked: true,
        revokedReason: "rotated",
        rotationOperationHash: operationHash,
        rotatedAt: now,
        replacedByTokenId: prepared.refreshTokenRecord.id,
      })
      .where(
        and(
          eq(refreshTokens.id, stored.id),
          eq(refreshTokens.revoked, false),
          gt(refreshTokens.expiresAt, now)
        )
      )
      .returning({ id: refreshTokens.id });

    if (!consumed) return false;

    await tx.insert(refreshTokens).values(prepared.refreshTokenRecord);
    return true;
  });

  if (!rotated) {
    const replacement = await replaceUnusedRefreshSuccessor(
      req,
      client,
      owner,
      stored.id,
      operationHash
    );
    if (replacement) {
      res.json(replacement);
      return;
    }

    const [latest] = await db
      .select({
        revoked: refreshTokens.revoked,
        revokedReason: refreshTokens.revokedReason,
      })
      .from(refreshTokens)
      .where(eq(refreshTokens.id, stored.id))
      .limit(1);

    if (
      latest?.revoked &&
      (latest.revokedReason ?? "rotated") === "rotated"
    ) {
      await revokeSessionsForReplay(req, client.id, stored.userId);
    }

    throw AppError.unauthorized("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  res.json(prepared.response);
});

// ─── POST /auth/logout ────────────────────────────────────────────

router.post("/logout", async (req: Request, res: Response) => {
  const {
    refreshToken: rawToken,
    clientId,
    clientSecret,
  } = clientTokenSchema.parse(req.body);
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
