import { and, eq } from "drizzle-orm";
import { db } from "../db";
import {
  permissions,
  rolePermissions,
  roles,
  serviceAccountRoles,
  serviceAccounts,
} from "../db/schema";
import { AppError } from "../utils/errors";

export async function getServiceAccountPermissions(
  serviceAccountId: string,
  clientId: string
): Promise<string[]> {
  const rows = await db
    .select({ resource: permissions.resource, action: permissions.action })
    .from(serviceAccountRoles)
    .innerJoin(
      rolePermissions,
      eq(rolePermissions.roleId, serviceAccountRoles.roleId)
    )
    .innerJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(
      and(
        eq(serviceAccountRoles.serviceAccountId, serviceAccountId),
        eq(serviceAccountRoles.clientId, clientId)
      )
    );

  return rows.map((row) => `${row.resource}:${row.action}`);
}

export async function assertServiceAccountBelongsToClient(
  serviceAccountId: string,
  clientId: string
) {
  const [serviceAccount] = await db
    .select()
    .from(serviceAccounts)
    .where(
      and(
        eq(serviceAccounts.id, serviceAccountId),
        eq(serviceAccounts.clientId, clientId)
      )
    )
    .limit(1);

  if (!serviceAccount) throw AppError.notFound("Service account not found");
  return serviceAccount;
}

export async function assertRoleBelongsToClient(
  roleId: string,
  clientId: string
) {
  const [role] = await db
    .select()
    .from(roles)
    .where(and(eq(roles.id, roleId), eq(roles.clientId, clientId)))
    .limit(1);

  if (!role) throw AppError.notFound("Role not found");
  return role;
}
