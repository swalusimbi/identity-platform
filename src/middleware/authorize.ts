import { Request, Response, NextFunction } from "express";
import { hasScope } from "../services/apiKey";
import { AppError } from "../utils/errors";

/**
 * Require a specific permission. Use after authenticate().
 *
 * Usage in routes:
 *   router.delete("/users/:id", authenticate, requirePermission("users:delete"), handler)
 *
 * Checks:
 *   - JWT users: checks permissions[] in the token payload
 *   - API key users: checks scopes[] on the key
 */
export function requirePermission(permission: string) {
  return (req: Request, _res: Response, next: NextFunction) => {
    // JWT-authenticated user
    if (req.user) {
      const perms = req.user.permissions || [];
      if (perms.includes("*") || perms.includes(permission)) {
        return next();
      }

      // Check wildcard: "users:*" matches "users:delete"
      const [resource] = permission.split(":");
      if (perms.includes(`${resource}:*`)) {
        return next();
      }

      throw AppError.forbidden(
        `Missing permission: ${permission}`,
        "INSUFFICIENT_PERMISSIONS"
      );
    }

    // API key-authenticated request
    if (req.apiKey) {
      if (hasScope(req.apiKey.scopes, permission)) {
        return next();
      }
      throw AppError.forbidden(
        `API key missing scope: ${permission}`,
        "INSUFFICIENT_SCOPE"
      );
    }

    throw AppError.unauthorized("Authentication required");
  };
}

/**
 * Require ANY of the listed permissions (OR logic)
 */
export function requireAnyPermission(...permissions: string[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    for (const perm of permissions) {
      try {
        requirePermission(perm)(req, _res, () => {});
        return next(); // First match wins
      } catch {
        continue;
      }
    }
    throw AppError.forbidden(
      `Requires one of: ${permissions.join(", ")}`,
      "INSUFFICIENT_PERMISSIONS"
    );
  };
}
