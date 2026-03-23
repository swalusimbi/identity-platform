import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import {
  roles,
  permissions,
  rolePermissions,
  userRoles,
} from "../db/schema";
import { eq, and, inArray } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate";
import { requirePermission } from "../middleware/authorize";
import { AppError } from "../utils/errors";

const router = Router();

// All role management requires authentication
router.use(authenticate);

// ─── Schemas ──────────────────────────────────────────────────────

const createRoleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().optional(),
  isDefault: z.boolean().optional(),
  permissionIds: z.array(z.string().uuid()).optional(),
});

const createPermissionSchema = z.object({
  resource: z.string().min(1).max(100),
  action: z.string().min(1).max(50),
  description: z.string().optional(),
});

const assignRoleSchema = z.object({
  userId: z.string().uuid(),
  roleId: z.string().uuid(),
});

// ─── Permissions CRUD ─────────────────────────────────────────────

// GET /roles/permissions — list all global permissions
router.get(
  "/permissions",
  requirePermission("roles:read"),
  async (_req: Request, res: Response) => {
    const all = await db.select().from(permissions);
    res.json(all);
  }
);

// POST /roles/permissions — create a new permission
router.post(
  "/permissions",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const body = createPermissionSchema.parse(req.body);

    const [perm] = await db
      .insert(permissions)
      .values(body)
      .onConflictDoNothing()
      .returning();

    if (!perm) throw AppError.conflict("Permission already exists");
    res.status(201).json(perm);
  }
);

// POST /roles/permissions/bulk — seed multiple permissions at once
router.post(
  "/permissions/bulk",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const schema = z.array(createPermissionSchema).min(1).max(100);
    const body = schema.parse(req.body);

    const created = await db
      .insert(permissions)
      .values(body)
      .onConflictDoNothing()
      .returning();

    res.status(201).json({ created: created.length, permissions: created });
  }
);

// ─── Roles CRUD ───────────────────────────────────────────────────

// GET /roles — list roles for the authenticated user's client
router.get(
  "/",
  requirePermission("roles:read"),
  async (req: Request, res: Response) => {
    const clientId = req.user!.cid;

    const clientRoles = await db
      .select()
      .from(roles)
      .where(eq(roles.clientId, clientId));

    // Attach permissions to each role
    const rolesWithPerms = await Promise.all(
      clientRoles.map(async (role) => {
        const perms = await db
          .select({
            id: permissions.id,
            resource: permissions.resource,
            action: permissions.action,
          })
          .from(rolePermissions)
          .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
          .where(eq(rolePermissions.roleId, role.id));

        return { ...role, permissions: perms };
      })
    );

    res.json(rolesWithPerms);
  }
);

// POST /roles — create a role for the current client
router.post(
  "/",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const body = createRoleSchema.parse(req.body);
    const clientId = req.user!.cid;

    const [role] = await db
      .insert(roles)
      .values({
        clientId,
        name: body.name,
        description: body.description,
        isDefault: body.isDefault ?? false,
      })
      .returning();

    // Attach permissions if provided
    if (body.permissionIds && body.permissionIds.length > 0) {
      await db.insert(rolePermissions).values(
        body.permissionIds.map((pid) => ({
          roleId: role.id,
          permissionId: pid,
        }))
      );
    }

    res.status(201).json(role);
  }
);

// PUT /roles/:id/permissions — replace all permissions on a role
router.put(
  "/:id/permissions",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const roleId = req.params.id;
    const clientId = req.user!.cid;

    const { permissionIds } = z
      .object({ permissionIds: z.array(z.string().uuid()) })
      .parse(req.body);

    // Verify role belongs to this client
    const [role] = await db
      .select()
      .from(roles)
      .where(and(eq(roles.id, roleId), eq(roles.clientId, clientId)))
      .limit(1);

    if (!role) throw AppError.notFound("Role not found");

    // Replace: delete existing, insert new
    await db.delete(rolePermissions).where(eq(rolePermissions.roleId, roleId));

    if (permissionIds.length > 0) {
      await db.insert(rolePermissions).values(
        permissionIds.map((pid) => ({ roleId, permissionId: pid }))
      );
    }

    res.json({ message: "Permissions updated", roleId, permissionIds });
  }
);

// DELETE /roles/:id
router.delete(
  "/:id",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const roleId = req.params.id;
    const clientId = req.user!.cid;

    const deleted = await db
      .delete(roles)
      .where(and(eq(roles.id, roleId), eq(roles.clientId, clientId)))
      .returning({ id: roles.id });

    if (deleted.length === 0) throw AppError.notFound("Role not found");
    res.json({ message: "Role deleted" });
  }
);

// ─── User role assignment ─────────────────────────────────────────

// POST /roles/assign — assign a role to a user
router.post(
  "/assign",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const { userId, roleId } = assignRoleSchema.parse(req.body);
    const clientId = req.user!.cid;

    // Verify role belongs to this client
    const [role] = await db
      .select()
      .from(roles)
      .where(and(eq(roles.id, roleId), eq(roles.clientId, clientId)))
      .limit(1);

    if (!role) throw AppError.notFound("Role not found");

    await db
      .insert(userRoles)
      .values({ userId, roleId, clientId })
      .onConflictDoNothing();

    res.json({ message: "Role assigned", userId, roleId });
  }
);

// POST /roles/revoke — remove a role from a user
router.post(
  "/revoke",
  requirePermission("roles:write"),
  async (req: Request, res: Response) => {
    const { userId, roleId } = assignRoleSchema.parse(req.body);
    const clientId = req.user!.cid;

    await db
      .delete(userRoles)
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.roleId, roleId),
          eq(userRoles.clientId, clientId)
        )
      );

    res.json({ message: "Role revoked", userId, roleId });
  }
);

export default router;
