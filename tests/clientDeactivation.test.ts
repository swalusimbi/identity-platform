import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app";
import { createTestClient, registerTestUser, seedDefaultRole, TestClient, TestUser } from "./helpers";

const ADMIN_KEY = process.env.ADMIN_KEY!;

/**
 * FUP-01: deactivating a client must stop its API keys immediately,
 * on both verification paths, for plain keys and service account keys.
 * API keys are checked per request, so deactivation reaches them at
 * once, unlike access tokens which ride out their TTL.
 */
describe("client deactivation and machine credentials", () => {
  let client: TestClient;
  let admin: TestUser;
  let plainKey: string;
  let serviceAccountKey: string;

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  const setActive = (isActive: boolean) =>
    request(app)
      .patch(`/clients/${client.id}`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ isActive });

  const verifyRemote = (apiKey: string) =>
    request(app).post("/auth/verify").send({ apiKey, audience: client.clientId });

  const verifyDirect = (apiKey: string) =>
    request(app).get("/api-keys").set("Authorization", `ApiKey ${apiKey}`);

  beforeAll(async () => {
    client = await createTestClient("deactivation-app");
    await seedDefaultRole(client.id, [
      { resource: "api-keys", action: "read" },
      { resource: "api-keys", action: "write" },
      { resource: "roles", action: "read" },
      { resource: "roles", action: "write" },
      { resource: "service-accounts", action: "write" },
    ]);
    admin = await registerTestUser(client, "deactivation-admin@example.com");

    const plain = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "plain", scopes: ["api-keys:read"] });
    plainKey = plain.body.key;

    // A service account key: no scopes, permissions from its role. The
    // role reuses the seeded api-keys:read permission so the SA key can
    // read /api-keys, our probe endpoint
    const perms = await request(app)
      .get("/roles/permissions")
      .set(auth(admin.accessToken));
    const readPerm = perms.body.find(
      (p: { resource: string; action: string }) =>
        p.resource === "api-keys" && p.action === "read"
    );
    const role = await request(app)
      .post("/roles")
      .set(auth(admin.accessToken))
      .send({ name: "machine", permissionIds: [readPerm.id] });
    const sa = await request(app)
      .post("/service-accounts")
      .set(auth(admin.accessToken))
      .send({ name: "reporter" });
    await request(app)
      .post(`/service-accounts/${sa.body.id}/roles`)
      .set(auth(admin.accessToken))
      .send({ roleId: role.body.id });
    const saKey = await request(app)
      .post(`/service-accounts/${sa.body.id}/api-keys`)
      .set(auth(admin.accessToken))
      .send({ name: "reporter-key" });
    serviceAccountKey = saKey.body.key;
  });

  it("both keys work while the client is active", async () => {
    expect((await verifyRemote(plainKey)).body.valid).toBe(true);
    expect((await verifyDirect(plainKey)).status).toBe(200);
    expect((await verifyRemote(serviceAccountKey)).body.valid).toBe(true);
    expect((await verifyDirect(serviceAccountKey)).status).toBe(200);
  });

  it("remote verification rejects both keys once the client is deactivated", async () => {
    await setActive(false);

    expect((await verifyRemote(plainKey)).body.valid).toBe(false);
    expect((await verifyRemote(serviceAccountKey)).body.valid).toBe(false);
  });

  it("direct API key auth rejects both keys once the client is deactivated", async () => {
    // (client is deactivated from the previous test)
    expect((await verifyDirect(plainKey)).status).toBe(401);
    expect((await verifyDirect(serviceAccountKey)).status).toBe(401);
  });

  it("reactivation restores both keys on both paths", async () => {
    await setActive(true);

    expect((await verifyRemote(plainKey)).body.valid).toBe(true);
    expect((await verifyDirect(plainKey)).status).toBe(200);
    expect((await verifyRemote(serviceAccountKey)).body.valid).toBe(true);
    expect((await verifyDirect(serviceAccountKey)).status).toBe(200);
  });
});
