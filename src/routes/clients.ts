import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import {
  clients,
  users,
  roles,
  permissions,
  rolePermissions,
  userRoles,
} from "../db/schema";
import { randomBytes, createHash, timingSafeEqual } from "crypto";
import { eq, and } from "drizzle-orm";
import { createAccountToken } from "../services/accountToken";
import { sendMail } from "../services/mailer";
import { audit } from "../services/audit";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

const router = Router();

/** Constant time comparison, hashing first to equalize lengths */
function requireAdminKey(provided: unknown): void {
  const expected = createHash("sha256").update(env.ADMIN_KEY).digest();
  const actual = createHash("sha256")
    .update(typeof provided === "string" ? provided : "")
    .digest();

  if (!timingSafeEqual(expected, actual)) {
    throw AppError.forbidden("Invalid admin key");
  }
}

const createClientSchema = z.object({
  name: z.string().min(1).max(255),
  redirectUris: z.array(z.string().url()).optional(),
  // Public clients (SPAs, mobile apps) get no secret and must use
  // PKCE for OAuth flows
  isPublic: z.boolean().optional(),
  // Set false for invite-only tenants, /auth/register is then closed
  allowUserRegistration: z.boolean().optional(),
  // Registered link targets for emailed tokens
  passwordResetUrl: z.string().url().optional(),
  emailVerifyUrl: z.string().url().optional(),
});

/**
 * POST /clients — register a new app client
 *
 * This is an admin-only endpoint. In production, protect it with
 * a master API key or restrict to localhost.
 *
 * For now: accessible via a shared secret header (X-Admin-Key)
 * that you set in the environment. Simple, effective for a single-operator setup.
 */
router.post("/", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);

  const body = createClientSchema.parse(req.body);
  const isPublic = body.isPublic ?? false;

  // Generate client credentials. Public clients have no secret.
  const clientId = `cl_${randomBytes(16).toString("base64url")}`;
  const clientSecret = isPublic
    ? null
    : `cs_${randomBytes(32).toString("base64url")}`;
  const clientSecretHash = clientSecret
    ? createHash("sha256").update(clientSecret).digest("hex")
    : null;

  const [client] = await db
    .insert(clients)
    .values({
      name: body.name,
      clientId,
      clientSecretHash,
      isPublic,
      allowUserRegistration: body.allowUserRegistration ?? true,
      redirectUris: body.redirectUris || [],
      passwordResetUrl: body.passwordResetUrl,
      emailVerifyUrl: body.emailVerifyUrl,
    })
    .returning({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      isPublic: clients.isPublic,
      allowUserRegistration: clients.allowUserRegistration,
      createdAt: clients.createdAt,
    });

  await audit(req, {
    clientId: client.id,
    action: "client.created",
    actorType: "operator",
    targetType: "client",
    targetId: client.id,
    details: { name: client.name, isPublic: client.isPublic },
  });

  // Return secret ONCE
  res.status(201).json({
    ...client,
    ...(clientSecret && {
      clientSecret, // ← Only time this is visible
      warning: "Store the client secret securely. It cannot be retrieved again.",
    }),
  });
});

// POST /clients/:id/rotate-secret — replace a client's secret (admin)
router.post("/:id/rotate-secret", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);
  const id = z.string().uuid().parse(req.params.id);

  const [existing] = await db
    .select({ isPublic: clients.isPublic })
    .from(clients)
    .where(eq(clients.id, id))
    .limit(1);

  if (!existing) throw AppError.notFound("Client not found");
  if (existing.isPublic) {
    throw AppError.badRequest("Public clients have no secret to rotate");
  }

  const clientSecret = `cs_${randomBytes(32).toString("base64url")}`;
  const clientSecretHash = createHash("sha256")
    .update(clientSecret)
    .digest("hex");

  const [client] = await db
    .update(clients)
    .set({ clientSecretHash, updatedAt: new Date() })
    .where(eq(clients.id, id))
    .returning({ id: clients.id, name: clients.name, clientId: clients.clientId });

  if (!client) throw AppError.notFound("Client not found");

  await audit(req, {
    clientId: client.id,
    action: "client.secret_rotated",
    actorType: "operator",
    targetType: "client",
    targetId: client.id,
  });

  // The old secret stops working immediately
  res.json({
    ...client,
    clientSecret,
    warning: "Store the client secret securely. It cannot be retrieved again.",
  });
});

// PATCH /clients/:id — update name, redirect URIs or active state (admin)
router.patch("/:id", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);
  const id = z.string().uuid().parse(req.params.id);

  const body = z
    .object({
      name: z.string().min(1).max(255).optional(),
      redirectUris: z.array(z.string().url()).optional(),
      isActive: z.boolean().optional(),
      allowUserRegistration: z.boolean().optional(),
      passwordResetUrl: z.string().url().nullable().optional(),
      emailVerifyUrl: z.string().url().nullable().optional(),
    })
    .refine((v) => Object.keys(v).length > 0, "No fields to update")
    .parse(req.body);

  const [client] = await db
    .update(clients)
    .set({ ...body, updatedAt: new Date() })
    .where(eq(clients.id, id))
    .returning({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      redirectUris: clients.redirectUris,
      isActive: clients.isActive,
      allowUserRegistration: clients.allowUserRegistration,
      passwordResetUrl: clients.passwordResetUrl,
      emailVerifyUrl: clients.emailVerifyUrl,
    });

  if (!client) throw AppError.notFound("Client not found");

  await audit(req, {
    clientId: client.id,
    action: "client.updated",
    actorType: "operator",
    targetType: "client",
    targetId: client.id,
    details: { fields: Object.keys(body) },
  });

  res.json(client);
});

// POST /clients/:id/bootstrap — set up a fresh tenant (admin)
// Creates the management role with its permissions and invites the
// first admin by email. Without this a new tenant has no user who
// could create roles or API keys.
const bootstrapSchema = z.object({
  adminEmail: z.string().email().max(320),
  roleName: z.string().min(1).max(100).default("admin"),
});

const MANAGEMENT_PERMISSIONS = [
  { resource: "users", action: "read", description: "View users" },
  { resource: "users", action: "write", description: "Create and manage users" },
  { resource: "roles", action: "read", description: "View roles and permissions" },
  { resource: "roles", action: "write", description: "Create, edit, assign roles" },
  { resource: "api-keys", action: "read", description: "View API keys" },
  { resource: "api-keys", action: "write", description: "Create and revoke API keys" },
];

router.post("/:id/bootstrap", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);
  const id = z.string().uuid().parse(req.params.id);
  const body = bootstrapSchema.parse(req.body);

  const [client] = await db
    .select()
    .from(clients)
    .where(eq(clients.id, id))
    .limit(1);

  if (!client) throw AppError.notFound("Client not found");
  if (!client.passwordResetUrl) {
    throw AppError.badRequest(
      "Set passwordResetUrl on the client first, the admin invite links there",
      "RESET_URL_NOT_CONFIGURED"
    );
  }

  const email = body.adminEmail.toLowerCase();
  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(and(eq(users.clientId, client.id), eq(users.email, email)))
    .limit(1);

  if (existing) {
    throw AppError.conflict("Email already registered for this client", "EMAIL_EXISTS");
  }

  // Management permissions and role, tolerant of reruns
  await db
    .insert(permissions)
    .values(MANAGEMENT_PERMISSIONS.map((p) => ({ ...p, clientId: client.id })))
    .onConflictDoNothing();

  const clientPerms = await db
    .select()
    .from(permissions)
    .where(eq(permissions.clientId, client.id));
  const mgmtPerms = clientPerms.filter((p) =>
    MANAGEMENT_PERMISSIONS.some(
      (m) => m.resource === p.resource && m.action === p.action
    )
  );

  let [role] = await db
    .select()
    .from(roles)
    .where(and(eq(roles.clientId, client.id), eq(roles.name, body.roleName)))
    .limit(1);

  if (!role) {
    [role] = await db
      .insert(roles)
      .values({
        clientId: client.id,
        name: body.roleName,
        description: "Tenant administration",
        isDefault: false,
      })
      .returning();
  }

  await db
    .insert(rolePermissions)
    .values(mgmtPerms.map((p) => ({ roleId: role.id, permissionId: p.id })))
    .onConflictDoNothing();

  // The admin sets their password through the emailed invite link
  const [admin] = await db
    .insert(users)
    .values({ clientId: client.id, email })
    .returning({ id: users.id, email: users.email });

  await db
    .insert(userRoles)
    .values({ userId: admin.id, roleId: role.id, clientId: client.id });

  const token = await createAccountToken(admin.id, "password_reset", 24);
  const link = new URL(client.passwordResetUrl);
  link.searchParams.set("token", token);

  // The tenant is fully set up at this point. A mail outage must not
  // undo that behind a 5xx: respond with a warning instead, the admin
  // gets their link through the password reset flow once mail is back.
  let inviteSent = true;
  try {
    await sendMail({
      to: email,
      subject: `You have been invited to administer ${client.name}`,
      text: [
        `You are the administrator for ${client.name}.`,
        "",
        `Set your password here (valid for 24 hours): ${link.toString()}`,
      ].join("\n"),
    });
  } catch {
    inviteSent = false;
  }

  await audit(req, {
    clientId: client.id,
    action: "client.bootstrapped",
    actorType: "operator",
    targetType: "client",
    targetId: client.id,
    details: { adminEmail: email, roleName: role.name, inviteSent },
  });

  res.status(201).json({
    user: admin,
    role: { id: role.id, name: role.name },
    permissions: mgmtPerms.map((p) => `${p.resource}:${p.action}`),
    message: inviteSent
      ? "Admin invited. The emailed link sets their password."
      : "Tenant bootstrapped, but the invite email failed to send.",
    ...(inviteSent
      ? {}
      : {
          warning:
            "The invite email could not be delivered. Once mail is back, the admin requests a link through the password reset flow.",
        }),
  });
});

// GET /clients — list registered clients (admin)
router.get("/", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);

  const all = await db
    .select({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      isActive: clients.isActive,
      createdAt: clients.createdAt,
    })
    .from(clients);

  res.json(all);
});

export default router;
