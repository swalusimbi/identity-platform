import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  TestClient,
  TestUser,
} from "./helpers";

describe("Service accounts", () => {
  let client: TestClient;
  let admin: TestUser;
  let usersReadRoleId: string;

  beforeAll(async () => {
    client = await createTestClient("service-accounts-app");
    await seedDefaultRole(client.id, [
      { resource: "roles", action: "read" },
      { resource: "roles", action: "write" },
      { resource: "service-accounts", action: "read" },
      { resource: "service-accounts", action: "write" },
      { resource: "api-keys", action: "read" },
    ]);
    admin = await registerTestUser(
      client,
      "service-accounts-admin@example.com"
    );

    const permission = await request(app)
      .post("/roles/permissions")
      .set(auth(admin.accessToken))
      .send({
        resource: "users",
        action: "read",
        description: "List users",
      });
    expect(permission.status).toBe(201);

    const role = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({
        name: "users-reader",
        permissionIds: [permission.body.id],
      });
    expect(role.status).toBe(201);
    usersReadRoleId = role.body.id;
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  async function createServiceAccount(roleIds: string[] = []) {
    const res = await request(app)
      .post("/service-accounts")
      .set(auth(admin.accessToken))
      .send({ name: `worker-${Date.now()}-${Math.random()}`, roleIds });
    expect(res.status).toBe(201);
    return res.body;
  }

  async function createServiceAccountKey(serviceAccountId: string) {
    const res = await request(app)
      .post(`/service-accounts/${serviceAccountId}/api-keys`)
      .set(auth(admin.accessToken))
      .send({ name: "worker-key" });
    expect(res.status).toBe(201);
    expect(res.body.key).toMatch(/^sk_/);
    return res.body;
  }

  it("creates and lists service accounts with role assignments", async () => {
    const account = await createServiceAccount([usersReadRoleId]);

    expect(account).toMatchObject({
      name: account.name,
      isActive: true,
      roleIds: [usersReadRoleId],
    });

    const list = await request(app)
      .get("/service-accounts")
      .set(auth(admin.accessToken));

    expect(list.status).toBe(200);
    const listed = list.body.find((item: { id: string }) => item.id === account.id);
    expect(listed).toBeTruthy();
    expect(listed.roleIds).toContain(usersReadRoleId);
  });

  it("creates service account keys without stored scopes", async () => {
    const account = await createServiceAccount([usersReadRoleId]);
    const key = await createServiceAccountKey(account.id);

    expect(key.serviceAccountId).toBe(account.id);
    expect(key.scopes).toEqual([]);

    const keys = await request(app)
      .get("/api-keys")
      .set(auth(admin.accessToken));
    expect(keys.status).toBe(200);
    const listed = keys.body.find((item: { id: string }) => item.id === key.id);
    expect(listed.serviceAccountId).toBe(account.id);
    expect(listed.scopes).toEqual([]);
    expect(listed.key).toBeUndefined();
  });

  it("resolves service account permissions live from roles", async () => {
    const account = await createServiceAccount();
    const key = await createServiceAccountKey(account.id);

    const deniedBefore = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key.key, requiredPermission: "users:read" });
    expect(deniedBefore.body).toMatchObject({
      valid: true,
      authorized: false,
    });

    const assign = await request(app)
      .post(`/service-accounts/${account.id}/roles`)
      .set(auth(admin.accessToken))
      .send({ roleId: usersReadRoleId });
    expect(assign.status).toBe(200);

    const allowed = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key.key, requiredPermission: "users:read" });
    expect(allowed.body).toMatchObject({
      valid: true,
      authorized: true,
      apiKey: {
        clientId: client.id,
        serviceAccount: { id: account.id, name: account.name },
      },
    });
    expect(allowed.body.apiKey.scopes).toEqual(["users:read"]);

    const users = await request(app)
      .get("/users")
      .set("Authorization", `ApiKey ${key.key}`);
    expect(users.status).toBe(200);

    const revoke = await request(app)
      .delete(`/service-accounts/${account.id}/roles/${usersReadRoleId}`)
      .set(auth(admin.accessToken));
    expect(revoke.status).toBe(200);

    const deniedAfter = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key.key, requiredPermission: "users:read" });
    expect(deniedAfter.body).toMatchObject({
      valid: true,
      authorized: false,
    });
  });

  it("invalidates all keys when a service account is deactivated", async () => {
    const account = await createServiceAccount([usersReadRoleId]);
    const key = await createServiceAccountKey(account.id);

    const active = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key.key, requiredPermission: "users:read" });
    expect(active.body).toMatchObject({ valid: true, authorized: true });

    const disabled = await request(app)
      .patch(`/service-accounts/${account.id}`)
      .set(auth(admin.accessToken))
      .send({ isActive: false });
    expect(disabled.status).toBe(200);

    const verify = await request(app)
      .post("/auth/verify")
      .send({ apiKey: key.key, requiredPermission: "users:read" });
    expect(verify.body).toMatchObject({
      valid: false,
      error: "Invalid or expired API key",
    });

    const users = await request(app)
      .get("/users")
      .set("Authorization", `ApiKey ${key.key}`);
    expect(users.status).toBe(401);
  });

  it("rejects role assignments from another client", async () => {
    const other = await createTestClient("service-accounts-other-app");
    await seedDefaultRole(other.id, [
      { resource: "roles", action: "write" },
      { resource: "service-accounts", action: "write" },
    ]);
    const otherAdmin = await registerTestUser(
      other,
      "service-accounts-other-admin@example.com"
    );

    const otherRole = await request(app)
      .post("/roles")
      .set(auth(otherAdmin.accessToken))
      .send({ name: "foreign-role" });
    expect(otherRole.status).toBe(201);

    const account = await createServiceAccount();
    const assign = await request(app)
      .post(`/service-accounts/${account.id}/roles`)
      .set(auth(admin.accessToken))
      .send({ roleId: otherRole.body.id });

    expect(assign.status).toBe(404);
    expect(assign.body.error).toBe("Role not found");
  });
});
