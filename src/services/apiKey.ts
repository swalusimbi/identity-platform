import { randomBytes, createHash } from "crypto";

const KEY_PREFIX = "sk_"; // "secret key" prefix, like Stripe's convention
const PREFIX_LENGTH = 8; // Visible prefix for identification

/**
 * Generate an API key with a visible prefix
 * Returns: { key: "sk_a1b2c3d4_...", prefix: "sk_a1b2c3d4", hash: "sha256..." }
 *
 * The full key is shown ONCE at creation. We store only the prefix + hash.
 * To verify: hash the incoming key and compare against stored hash.
 */
export function generateApiKey(): {
  key: string;
  prefix: string;
  hash: string;
} {
  const random = randomBytes(32).toString("base64url");
  const prefix = `${KEY_PREFIX}${random.slice(0, PREFIX_LENGTH)}`;
  const key = `${prefix}_${random.slice(PREFIX_LENGTH)}`;
  const hash = hashApiKey(key);

  return { key, prefix, hash };
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/**
 * Check if a list of scopes satisfies a required scope
 * Supports wildcards: "users:*" matches "users:read", "users:write"
 */
export function hasScope(
  grantedScopes: string[],
  requiredScope: string
): boolean {
  return grantedScopes.some((scope) => {
    if (scope === "*") return true; // Superkey
    if (scope === requiredScope) return true;

    // Wildcard: "users:*" matches "users:read"
    const [resource, action] = scope.split(":");
    const [reqResource, _reqAction] = requiredScope.split(":");
    return resource === reqResource && action === "*";
  });
}
