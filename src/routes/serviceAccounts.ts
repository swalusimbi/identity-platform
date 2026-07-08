import { Router, Request, Response } from "express";
import { z } from "zod";
import { and, eq, inArray, ne } from "drizzle-orm";
import { db } from "../db";
import {
  apiKeys,
  roles,
  serviceAccountRoles,
  serviceAccounts,
} from "../db/schema";
import { authenticate, authenticatedClientId } from "../middleware/authenticate";
import { requirePermission } from "../middleware/authorize";
import { generateApiKey } from "../services/apiKey";
import { audit, auditActor } from "../services/audit";
import {
  assertRoleBelongsToClient,
  assertServiceAccountBelongsToClient,
} from "../services/serviceAccount";
import { AppError } from "../utils/errors";

const router = Router();

router.use(authenticate);

const createServiceAccountSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(2000).optional(),
  roleIds: z.array(z.string().uuid()).default([]),
});

const updateServiceAccountSchema = z
  .object({
    name: z.string().min(1).max(255).optional(),
    description: z.string().max(2000).nullable().optional(),
    isActive: z.boolean().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, "No fields to update");

const assignRoleSchema = z.object({
  roleId: z.string().uuid(),
});

const createKeySchema = z.object({
  name: z.string().min(1).max(255),
  expiresInDays: z.number().int().min(1).max(365).optional(),
});

async function assertRolesBelongToClient(
  roleIds: string[],
  clientId: string
): Promise<void> {
  if (roleIds.length === 0) return;

  const uniqueRoleIds = [...new Set(roleIds)];
  const owned = await db
    .select({ id: roles.id })
    .from(roles)
    .where(and(inArray(roles.id, uniqueRoleIds), eq(roles.clientId, clientId)));

  if (owned.length !== uniqueRoleIds.length) {
    throw AppError.badRequest(
      "One or more roles do not exist for this client",
      "UNKNOWN_ROLE"
    );
  }
}

async function serviceAccountRoleIds(
  serviceAccountId: string,
  clientId: string
): Promise<string[]> {
  const assigned = await db
    .select({ roleId: serviceAccountRoles.roleId })
    .from(serviceAccountRoles)
    .where(
      and(
        eq(serviceAccountRoles.serviceAccountId, serviceAccountId),
        eq(serviceAccountRoles.clientId, clientId)
      )
    );

  return assigned.map((role) => role.roleId);
}

// GET /service-accounts - list service accounts for the current client
router.get(
  "/",
  requirePermission("service-accounts:read"),
  async (req: Request, res: Response) => {
    const clientId = authenticatedClientId(req);

    const accounts = await db
      .select()
      .from(serviceAccounts)
      .where(eq(serviceAccounts.clientId, clientId));

    const withRoles = await Promise.all(
      accounts.map(async (account) => ({
        ...account,
        roleIds: await serviceAccountRoleIds(account.id, clientId),
      }))
    );

    res.json(withRoles);
  }
);

// POST /service-accounts - create a role-bearing machine principal
router.post(
  "/",
  requirePermission("service-accounts:write"),
  async (req: Request, res: Response) => {
    const body = createServiceAccountSchema.parse(req.body);
    const clientId = authenticatedClientId(req);
    const roleIds = [...new Set(body.roleIds)];

    await assertRolesBelongToClient(roleIds, clientId);

    const [account] = await db
      .insert(serviceAccounts)
      .values({
        clientId,
        name: body.name,
        description: body.description,
      })
      .onConflictDoNothing()
      .returning();

    if (!account) throw AppError.conflict("Service account already exists");

    if (roleIds.length > 0) {
      await db.insert(serviceAccountRoles).values(
        roleIds.map((roleId) => ({
          serviceAccountId: account.id,
          roleId,
          clientId,
        }))
      );
    }

    await audit(req, {
      clientId,
      action: "service_account.created",
      ...auditActor(req),
      targetType: "service_account",
      targetId: account.id,
      details: { name: account.name, roleIds },
    });

    res.status(201).json({ ...account, roleIds });
  }
);

// PATCH /service-accounts/:id - update name, description or active flag
router.patch(
  "/:id",
  requirePermission("service-accounts:write"),
  async (req: Request, res: Response) => {
    const id = z.string().uuid().parse(req.params.id);
    const body = updateServiceAccountSchema.parse(req.body);
    const clientId = authenticatedClientId(req);

    if (body.name) {
      const [existing] = await db
        .select({ id: serviceAccounts.id })
        .from(serviceAccounts)
        .where(
          and(
            eq(serviceAccounts.clientId, clientId),
            eq(serviceAccounts.name, body.name),
            ne(serviceAccounts.id, id)
          )
        )
        .limit(1);

      if (existing) throw AppError.conflict("Service account already exists");
    }

    const [account] = await db
      .update(serviceAccounts)
      .set({ ...body, updatedAt: new Date() })
      .where(and(eq(serviceAccounts.id, id), eq(serviceAccounts.clientId, clientId)))
      .returning();

    if (!account) throw AppError.notFound("Service account not found");

    await audit(req, {
      clientId,
      action: "service_account.updated",
      ...auditActor(req),
      targetType: "service_account",
      targetId: account.id,
      details: { fields: Object.keys(body) },
    });

    res.json({
      ...account,
      roleIds: await serviceAccountRoleIds(account.id, clientId),
    });
  }
);

// POST /service-accounts/:id/roles - assign a role to a service account
router.post(
  "/:id/roles",
  requirePermission("service-accounts:write"),
  async (req: Request, res: Response) => {
    const serviceAccountId = z.string().uuid().parse(req.params.id);
    const { roleId } = assignRoleSchema.parse(req.body);
    const clientId = authenticatedClientId(req);

    const account = await assertServiceAccountBelongsToClient(
      serviceAccountId,
      clientId
    );
    const role = await assertRoleBelongsToClient(roleId, clientId);

    await db
      .insert(serviceAccountRoles)
      .values({ serviceAccountId, roleId, clientId })
      .onConflictDoNothing();

    await audit(req, {
      clientId,
      action: "service_account.role_assigned",
      ...auditActor(req),
      targetType: "service_account",
      targetId: account.id,
      details: { roleId, roleName: role.name },
    });

    res.json({ message: "Role assigned", serviceAccountId, roleId });
  }
);

// DELETE /service-accounts/:id/roles/:roleId - revoke a service account role
router.delete(
  "/:id/roles/:roleId",
  requirePermission("service-accounts:write"),
  async (req: Request, res: Response) => {
    const serviceAccountId = z.string().uuid().parse(req.params.id);
    const roleId = z.string().uuid().parse(req.params.roleId);
    const clientId = authenticatedClientId(req);

    const account = await assertServiceAccountBelongsToClient(
      serviceAccountId,
      clientId
    );

    await db
      .delete(serviceAccountRoles)
      .where(
        and(
          eq(serviceAccountRoles.serviceAccountId, serviceAccountId),
          eq(serviceAccountRoles.roleId, roleId),
          eq(serviceAccountRoles.clientId, clientId)
        )
      );

    await audit(req, {
      clientId,
      action: "service_account.role_revoked",
      ...auditActor(req),
      targetType: "service_account",
      targetId: account.id,
      details: { roleId },
    });

    res.json({ message: "Role revoked", serviceAccountId, roleId });
  }
);

// POST /service-accounts/:id/api-keys - create a credential for the account
router.post(
  "/:id/api-keys",
  requirePermission("service-accounts:write"),
  async (req: Request, res: Response) => {
    const serviceAccountId = z.string().uuid().parse(req.params.id);
    const body = createKeySchema.parse(req.body);
    const clientId = authenticatedClientId(req);
    const account = await assertServiceAccountBelongsToClient(
      serviceAccountId,
      clientId
    );

    if (!account.isActive) {
      throw AppError.badRequest(
        "Cannot create a key for an inactive service account",
        "SERVICE_ACCOUNT_INACTIVE"
      );
    }

    const { key, prefix, hash } = generateApiKey();
    const expiresAt = body.expiresInDays
      ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000)
      : null;

    const [created] = await db
      .insert(apiKeys)
      .values({
        clientId,
        serviceAccountId,
        keyPrefix: prefix,
        keyHash: hash,
        name: body.name,
        scopes: [],
        expiresAt,
      })
      .returning({
        id: apiKeys.id,
        serviceAccountId: apiKeys.serviceAccountId,
        name: apiKeys.name,
        keyPrefix: apiKeys.keyPrefix,
        scopes: apiKeys.scopes,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
      });

    await audit(req, {
      clientId,
      action: "service_account.key_created",
      ...auditActor(req),
      targetType: "api_key",
      targetId: created.id,
      details: { serviceAccountId, name: created.name },
    });

    res.status(201).json({
      ...created,
      key,
      warning: "Store this key securely. It cannot be retrieved again.",
    });
  }
);

export default router;
