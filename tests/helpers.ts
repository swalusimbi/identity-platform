import request from "supertest";
import { randomUUID } from "crypto";
import app from "../src/app";
import { db } from "../src/db";
import { roles, permissions, rolePermissions } from "../src/db/schema";

const ADMIN_KEY = process.env.ADMIN_KEY!;

/**
 * Random fake client IP per logical actor so the per-IP rate limiter
 * (5 req/min on register and login) never trips across tests. Random
 * rather than a counter because each test file runs in its own process.
 * Avoids 10.99.x.x, which rateLimit.test.ts owns. Works because the
 * app sets trust proxy = 1.
 */
export function uniqueIp(): string {
  const octet = () => 1 + Math.floor(Math.random() * 250);
  return `10.${Math.floor(Math.random() * 98)}.${octet()}.${octet()}`;
}

export function refreshOperationId(): string {
  return randomUUID();
}

export interface TestClient {
  id: string; // internal UUID
  clientId: string; // cl_...
  clientSecret?: string; // cs_..., absent for public clients
}

/** Register an app client through the admin endpoint */
export async function createTestClient(
  name: string,
  opts: {
    isPublic?: boolean;
    redirectUris?: string[];
    passwordResetUrl?: string;
    emailVerifyUrl?: string;
    allowUserRegistration?: boolean;
  } = {}
): Promise<TestClient> {
  const res = await request(app)
    .post("/clients")
    .set("X-Admin-Key", ADMIN_KEY)
    .send({ name, ...opts });

  if (res.status !== 201) {
    throw new Error(`createTestClient failed: ${res.status} ${res.text}`);
  }

  return {
    id: res.body.id,
    clientId: res.body.clientId,
    clientSecret: res.body.clientSecret,
  };
}

/**
 * Seed a default role for a client carrying the given permissions
 * (created on the fly). Users registered afterwards get the role
 * automatically, so their tokens carry the permissions.
 */
export async function seedDefaultRole(
  clientUuid: string,
  perms: { resource: string; action: string }[],
  roleName = "default"
): Promise<void> {
  const [role] = await db
    .insert(roles)
    .values({ clientId: clientUuid, name: roleName, isDefault: true })
    .returning();

  if (perms.length === 0) return;

  const inserted = await db
    .insert(permissions)
    .values(perms.map((p) => ({ ...p, clientId: clientUuid })))
    .returning();

  await db
    .insert(rolePermissions)
    .values(inserted.map((p) => ({ roleId: role.id, permissionId: p.id })));
}

export interface TestUser {
  id: string;
  email: string;
  password: string;
  accessToken: string;
  refreshToken: string;
}

/** Register a user under a client and return their tokens */
export async function registerTestUser(
  client: TestClient,
  email: string,
  password = "test-password-123"
): Promise<TestUser> {
  const res = await request(app)
    .post("/auth/register")
    .set("X-Forwarded-For", uniqueIp())
    .send({
      email,
      password,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });

  if (res.status !== 201) {
    throw new Error(`registerTestUser failed: ${res.status} ${res.text}`);
  }

  return {
    id: res.body.user.id,
    email,
    password,
    accessToken: res.body.accessToken,
    refreshToken: res.body.refreshToken,
  };
}
