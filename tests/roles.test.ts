import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  uniqueIp,
  TestClient,
  TestUser,
} from "./helpers";

describe("roles and permissions", () => {
  let client: TestClient;
  let admin: TestUser;

  beforeAll(async () => {
    client = await createTestClient("roles-app");
    await seedDefaultRole(client.id, [
      { resource: "roles", action: "read" },
      { resource: "roles", action: "write" },
    ]);
    admin = await registerTestUser(client, "roles-admin@example.com");
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("requires authentication", async () => {
    const res = await request(app).get("/roles");
    expect(res.status).toBe(401);
  });

  it("lists the client's roles with their permissions", async () => {
    const res = await request(app).get("/roles").set(auth(admin.accessToken));

    expect(res.status).toBe(200);
    const names = res.body.map((r: { name: string }) => r.name);
    expect(names).toContain("default");
    const def = res.body.find((r: { name: string }) => r.name === "default");
    expect(def.permissions.length).toBe(2);
  });

  it("creates a role, replaces its permissions and assigns it", async () => {
    // New permission to attach
    const permRes = await request(app)
      .post("/roles/permissions")
      .set(auth(admin.accessToken))
      .send({ resource: "invoices", action: "write" });
    expect(permRes.status).toBe(201);

    // Create role with that permission
    const roleRes = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({ name: "billing", permissionIds: [permRes.body.id] });
    expect(roleRes.status).toBe(201);

    // Assign to a fresh user
    const member = await registerTestUser(client, "roles-member@example.com");
    const assign = await request(app)
      .post("/roles/assign")
      .set(auth(admin.accessToken))
      .send({ userId: member.id, roleId: roleRes.body.id });
    expect(assign.status).toBe(200);

    // Next login carries the new permission
    const relogin = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: member.email,
        password: member.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(relogin.status).toBe(200);

    const verify = await request(app)
      .post("/auth/verify")
      .send({ token: relogin.body.accessToken, audience: client.clientId });
    expect(verify.body.user.permissions).toContain("invoices:write");

    // Revoke and confirm it is gone on the next login
    const revoke = await request(app)
      .post("/roles/revoke")
      .set(auth(admin.accessToken))
      .send({ userId: member.id, roleId: roleRes.body.id });
    expect(revoke.status).toBe(200);

    const relogin2 = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: member.email,
        password: member.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    const verify2 = await request(app)
      .post("/auth/verify")
      .send({ token: relogin2.body.accessToken, audience: client.clientId });
    expect(verify2.body.user.permissions).not.toContain("invoices:write");
  });

  it("blocks users without roles:write from managing roles", async () => {
    const other = await createTestClient("roles-unpriv-app");
    const peon = await registerTestUser(other, "peon@example.com");

    const res = await request(app)
      .post("/roles")
      .set(auth(peon.accessToken))
      .send({ name: "sneaky" });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe("INSUFFICIENT_PERMISSIONS");
  });

  it("only lists the client's own permissions", async () => {
    const other = await createTestClient("perm-isolation-app");
    await seedDefaultRole(other.id, [
      { resource: "roles", action: "read" },
      { resource: "secrets", action: "read" },
    ], "perm-isolation-default");
    const rival = await registerTestUser(other, "perm-iso@example.com");

    const mine = await request(app)
      .get("/roles/permissions")
      .set(auth(rival.accessToken));
    expect(mine.status).toBe(200);
    const names = mine.body.map(
      (p: { resource: string; action: string }) => `${p.resource}:${p.action}`
    );
    expect(names).toContain("secrets:read");
    expect(names).not.toContain("invoices:write"); // belongs to the other client

    const theirs = await request(app)
      .get("/roles/permissions")
      .set(auth(admin.accessToken));
    expect(
      theirs.body.map((p: { resource: string }) => p.resource)
    ).not.toContain("secrets");
  });

  it("rejects attaching another client's permission to a role", async () => {
    // A permission owned by `client`
    const perm = await request(app)
      .post("/roles/permissions")
      .set(auth(admin.accessToken))
      .send({ resource: "cross", action: "write" });
    expect(perm.status).toBe(201);

    const other = await createTestClient("perm-attach-app");
    await seedDefaultRole(other.id, [
      { resource: "roles", action: "write" },
    ], "perm-attach-default");
    const rival = await registerTestUser(other, "perm-attach@example.com");

    const res = await request(app)
      .post("/roles")
      .set(auth(rival.accessToken))
      .send({ name: "stealer", permissionIds: [perm.body.id] });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("UNKNOWN_PERMISSION");
  });

  it("does not let one client touch another client's roles", async () => {
    // Role created under `client`, fetched as a user of another client
    const roleList = await request(app)
      .get("/roles")
      .set(auth(admin.accessToken));
    const foreignRoleId = roleList.body[0].id;

    const other = await createTestClient("roles-foreign-app");
    await seedDefaultRole(other.id, [
      { resource: "roles", action: "write" },
    ], "foreign-default");
    const rival = await registerTestUser(other, "rival@example.com");

    const del = await request(app)
      .delete(`/roles/${foreignRoleId}`)
      .set(auth(rival.accessToken));
    expect(del.status).toBe(404);
  });

  it("does not assign this client's role to another client's user", async () => {
    const roleRes = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({ name: "local-only" });
    expect(roleRes.status).toBe(201);

    const other = await createTestClient("roles-foreign-user-app");
    const foreignUser = await registerTestUser(other, "foreign-user@example.com");

    const res = await request(app)
      .post("/roles/assign")
      .set(auth(admin.accessToken))
      .send({ userId: foreignUser.id, roleId: roleRes.body.id });

    expect(res.status).toBe(404);
  });

  it("does not revoke this client's role from another client's user", async () => {
    const roleRes = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({ name: "local-revoke-only" });
    expect(roleRes.status).toBe(201);

    const other = await createTestClient("roles-foreign-revoke-app");
    const foreignUser = await registerTestUser(other, "foreign-revoke@example.com");

    const res = await request(app)
      .post("/roles/revoke")
      .set(auth(admin.accessToken))
      .send({ userId: foreignUser.id, roleId: roleRes.body.id });

    expect(res.status).toBe(404);
  });
});

describe("wildcard permissions on user tokens", () => {
  let client: TestClient;
  let wildcard: TestUser;

  beforeAll(async () => {
    client = await createTestClient("wildcard-app");
    await seedDefaultRole(client.id, [
      { resource: "roles", action: "*" },
    ], "wildcard-default");
    wildcard = await registerTestUser(client, "wildcard@example.com");
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("satisfies requirePermission through a resource wildcard", async () => {
    // roles:* must satisfy both roles:read and roles:write guards
    const read = await request(app)
      .get("/roles")
      .set(auth(wildcard.accessToken));
    expect(read.status).toBe(200);

    const write = await request(app)
      .post("/roles/permissions")
      .set(auth(wildcard.accessToken))
      .send({ resource: "reports", action: "read" });
    expect(write.status).toBe(201);
  });

  it("does not let a wildcard cross its resource", async () => {
    const res = await request(app)
      .get("/users")
      .set(auth(wildcard.accessToken));
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("INSUFFICIENT_PERMISSIONS");
  });

  it("authorizes wildcard tokens on /auth/verify", async () => {
    const token = wildcard.accessToken;

    const covered = await request(app)
      .post("/auth/verify")
      .send({
        token,
        audience: client.clientId,
        requiredPermission: "roles:write",
      });
    expect(covered.body).toMatchObject({ valid: true, authorized: true });
    expect(covered.body.user.permissions).toContain("roles:*");

    const outside = await request(app)
      .post("/auth/verify")
      .send({
        token,
        audience: client.clientId,
        requiredPermission: "users:read",
      });
    expect(outside.body).toMatchObject({ valid: true, authorized: false });
  });
});
