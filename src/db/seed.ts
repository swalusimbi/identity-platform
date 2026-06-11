/**
 * Seed script — run once after first deployment
 *
 * Usage:
 *   DATABASE_URL=... JWT_SECRET=... ADMIN_KEY=... npx tsx src/db/seed.ts
 *
 * Optional overrides:
 *   SEED_CLIENT_NAME=My App
 *   SEED_ADMIN_EMAIL=admin@myapp.com
 *   SEED_REDIRECT_URIS=https://myapp.com/auth/callback,https://myapp.com/cb
 *
 * Creates:
 *   1. Core permissions (RBAC, users, api-keys)
 *   2. A default client (for your first app)
 *   3. An "admin" role with all permissions
 *   4. An admin user with that role
 */

import { db, sql } from "./index";
import {
  permissions,
  clients,
  roles,
  rolePermissions,
  users,
  userRoles,
} from "./schema";
import { randomBytes, createHash } from "crypto";
import { hashPassword } from "../services/password";

const CLIENT_NAME = process.env.SEED_CLIENT_NAME || "Default App";
const ADMIN_EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@example.com";
const REDIRECT_URIS = (process.env.SEED_REDIRECT_URIS || "https://app.example.com")
  .split(",")
  .map((uri) => uri.trim())
  .filter(Boolean);

async function seed() {
  console.log("🌱 Seeding auth_service database...\n");

  // ─── 1. Seed permissions ──────────────────────────────────────

  const corePermissions = [
    { resource: "users", action: "read", description: "View user profiles" },
    { resource: "users", action: "write", description: "Create and update users" },
    { resource: "users", action: "delete", description: "Delete users" },
    { resource: "roles", action: "read", description: "View roles and permissions" },
    { resource: "roles", action: "write", description: "Create, edit, assign roles" },
    { resource: "api-keys", action: "read", description: "View API keys" },
    { resource: "api-keys", action: "write", description: "Create and revoke API keys" },
    // Add your app-specific permissions here:
    // { resource: "billing", action: "read", description: "View billing data" },
    // { resource: "meters", action: "write", description: "Manage meters" },
  ];

  const insertedPerms = await db
    .insert(permissions)
    .values(corePermissions)
    .onConflictDoNothing()
    .returning();

  console.log(`✓ ${insertedPerms.length} permissions seeded`);

  // ─── 2. Create default client ─────────────────────────────────

  const clientId = `cl_${randomBytes(16).toString("base64url")}`;
  const clientSecret = `cs_${randomBytes(32).toString("base64url")}`;
  const clientSecretHash = createHash("sha256").update(clientSecret).digest("hex");

  const [client] = await db
    .insert(clients)
    .values({
      name: CLIENT_NAME,
      clientId,
      clientSecretHash,
      redirectUris: REDIRECT_URIS,
    })
    .returning();

  console.log(`✓ Default client created`);
  console.log(`  Client ID:     ${clientId}`);
  console.log(`  Client Secret: ${clientSecret}`);
  console.log(`  ⚠ Save the secret — it won't be shown again!\n`);

  // ─── 3. Create admin role with ALL permissions ────────────────

  const [adminRole] = await db
    .insert(roles)
    .values({
      clientId: client.id,
      name: "admin",
      description: "Full access to all resources",
      isDefault: false,
    })
    .returning();

  // Create a default "user" role with read-only
  const readPerms = insertedPerms.filter((p) => p.action === "read");
  const [userRole] = await db
    .insert(roles)
    .values({
      clientId: client.id,
      name: "user",
      description: "Standard user with read access",
      isDefault: true, // Auto-assigned on registration
    })
    .returning();

  // Assign all permissions to admin
  if (insertedPerms.length > 0) {
    await db.insert(rolePermissions).values(
      insertedPerms.map((p) => ({
        roleId: adminRole.id,
        permissionId: p.id,
      }))
    );
  }

  // Assign read permissions to user role
  if (readPerms.length > 0) {
    await db.insert(rolePermissions).values(
      readPerms.map((p) => ({
        roleId: userRole.id,
        permissionId: p.id,
      }))
    );
  }

  console.log(`✓ Roles created: admin (${insertedPerms.length} perms), user (${readPerms.length} perms)`);

  // ─── 4. Create admin user ────────────────────────────────────

  const adminEmail = ADMIN_EMAIL.toLowerCase();
  const adminPassword = randomBytes(16).toString("base64url");
  const passwordHash = await hashPassword(adminPassword);

  const [adminUser] = await db
    .insert(users)
    .values({
      clientId: client.id,
      email: adminEmail,
      passwordHash,
      emailVerified: true,
    })
    .returning();

  await db.insert(userRoles).values({
    userId: adminUser.id,
    roleId: adminRole.id,
    clientId: client.id,
  });

  console.log(`\n✓ Admin user created`);
  console.log(`  Email:    ${adminEmail}`);
  console.log(`  Password: ${adminPassword}`);
  console.log(`  ⚠ Change this password after first login!\n`);

  console.log("🎉 Seed complete. Save the credentials above.");

  await sql.end();
  process.exit(0);
}

seed().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
