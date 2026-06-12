import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { users, clients, roles, userRoles, refreshTokens } from "../db/schema";
import { eq, and, inArray } from "drizzle-orm";
import { authenticate, authenticatedClientId } from "../middleware/authenticate";
import { requirePermission } from "../middleware/authorize";
import { createAccountToken } from "../services/accountToken";
import { sendMail } from "../services/mailer";
import { AppError } from "../utils/errors";

const router = Router();

router.use(authenticate);

// ─── Schemas ──────────────────────────────────────────────────────

const createUserSchema = z.object({
  email: z.string().email().max(320),
  roleIds: z.array(z.string().uuid()).optional(),
  // Invites email a set-password link (24h). Disable for accounts
  // that will only ever sign in through OAuth.
  sendInvite: z.boolean().default(true),
});

const updateUserSchema = z.object({
  isActive: z.boolean(),
});

// ─── POST /users — provision a user (invite flow) ─────────────────

router.post(
  "/",
  requirePermission("users:write"),
  async (req: Request, res: Response) => {
    const body = createUserSchema.parse(req.body);
    const clientId = authenticatedClientId(req);
    const email = body.email.toLowerCase();

    const [client] = await db
      .select()
      .from(clients)
      .where(eq(clients.id, clientId))
      .limit(1);
    if (!client) throw AppError.unauthorized("Client not found");

    if (body.sendInvite && !client.passwordResetUrl) {
      throw AppError.badRequest(
        "Set passwordResetUrl on the client first, invites link there",
        "RESET_URL_NOT_CONFIGURED"
      );
    }

    const [existing] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.clientId, clientId), eq(users.email, email)))
      .limit(1);
    if (existing) throw AppError.conflict("Email already registered", "EMAIL_EXISTS");

    // Roles must belong to this client
    const roleIds = body.roleIds ?? [];
    if (roleIds.length > 0) {
      const owned = await db
        .select({ id: roles.id })
        .from(roles)
        .where(and(inArray(roles.id, roleIds), eq(roles.clientId, clientId)));
      if (owned.length !== new Set(roleIds).size) {
        throw AppError.badRequest(
          "One or more roles do not exist for this client",
          "UNKNOWN_ROLE"
        );
      }
    }

    // No password, the invite link sets it
    const [user] = await db
      .insert(users)
      .values({ clientId, email })
      .returning({ id: users.id, email: users.email });

    if (roleIds.length > 0) {
      await db
        .insert(userRoles)
        .values(roleIds.map((roleId) => ({ userId: user.id, roleId, clientId })));
    }

    if (body.sendInvite) {
      const token = await createAccountToken(user.id, "password_reset", 24);
      const link = new URL(client.passwordResetUrl!);
      link.searchParams.set("token", token);

      await sendMail({
        to: email,
        subject: `Your ${client.name} account`,
        text: [
          `An account has been created for you at ${client.name}.`,
          "",
          `Set your password here (valid for 24 hours): ${link.toString()}`,
        ].join("\n"),
      });
    }

    res.status(201).json({
      id: user.id,
      email: user.email,
      roleIds,
      invited: body.sendInvite,
    });
  }
);

// ─── GET /users — list the client's users ─────────────────────────

router.get(
  "/",
  requirePermission("users:read"),
  async (req: Request, res: Response) => {
    const clientId = authenticatedClientId(req);

    const all = await db
      .select({
        id: users.id,
        email: users.email,
        emailVerified: users.emailVerified,
        isActive: users.isActive,
        oauthProvider: users.oauthProvider,
        createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.clientId, clientId))
      .orderBy(users.createdAt);

    res.json(all);
  }
);

// ─── PATCH /users/:id — deactivate or reactivate ──────────────────

router.patch(
  "/:id",
  requirePermission("users:write"),
  async (req: Request, res: Response) => {
    const userId = z.string().uuid().parse(req.params.id);
    const body = updateUserSchema.parse(req.body);
    const clientId = authenticatedClientId(req);

    const [updated] = await db
      .update(users)
      .set({ isActive: body.isActive, updatedAt: new Date() })
      .where(and(eq(users.id, userId), eq(users.clientId, clientId)))
      .returning({ id: users.id, email: users.email, isActive: users.isActive });

    if (!updated) throw AppError.notFound("User not found");

    // Offboarding: kill every session now. Outstanding access tokens
    // still ride out their TTL, that window is the documented contract.
    if (!body.isActive) {
      await db
        .update(refreshTokens)
        .set({ revoked: true })
        .where(eq(refreshTokens.userId, userId));
    }

    res.json(updated);
  }
);

export default router;
