import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";
import { createTestClient, uniqueIp } from "./helpers";

const ADMIN_KEY = process.env.ADMIN_KEY!;

describe("client registration (admin)", () => {
  it("rejects requests without the admin key", async () => {
    const res = await request(app).post("/clients").send({ name: "nope" });
    expect(res.status).toBe(403);
  });

  it("rejects a wrong admin key", async () => {
    const res = await request(app)
      .post("/clients")
      .set("X-Admin-Key", "wrong-key")
      .send({ name: "nope" });
    expect(res.status).toBe(403);
  });

  it("creates a client and returns the secret exactly once", async () => {
    const res = await request(app)
      .post("/clients")
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ name: "client-test-app", redirectUris: ["https://app.example.com/cb"] });

    expect(res.status).toBe(201);
    expect(res.body.clientId).toMatch(/^cl_/);
    expect(res.body.clientSecret).toMatch(/^cs_/);
    expect(res.body.warning).toBeTruthy();

    // Listing never exposes the secret
    const list = await request(app).get("/clients").set("X-Admin-Key", ADMIN_KEY);
    expect(list.status).toBe(200);
    const created = list.body.find(
      (c: { clientId: string }) => c.clientId === res.body.clientId
    );
    expect(created).toBeTruthy();
    expect(created.clientSecret).toBeUndefined();
    expect(created.clientSecretHash).toBeUndefined();
  });
});

describe("client lifecycle (admin)", () => {
  // Login with an unknown email: INVALID_CLIENT means the secret was
  // rejected, INVALID_CREDENTIALS means it was accepted
  const probeSecret = (clientId: string, clientSecret: string) =>
    request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "probe@example.com",
        password: "probe-password",
        clientId,
        clientSecret,
      });

  it("rotates the secret and invalidates the old one immediately", async () => {
    const client = await createTestClient("rotate-app");

    const res = await request(app)
      .post(`/clients/${client.id}/rotate-secret`)
      .set("X-Admin-Key", ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.clientSecret).toMatch(/^cs_/);
    expect(res.body.clientSecret).not.toBe(client.clientSecret);

    const oldSecret = await probeSecret(client.clientId, client.clientSecret);
    expect(oldSecret.body.code).toBe("INVALID_CLIENT");

    const newSecret = await probeSecret(client.clientId, res.body.clientSecret);
    expect(newSecret.body.code).toBe("INVALID_CREDENTIALS");
  });

  it("deactivates and reactivates a client", async () => {
    const client = await createTestClient("deactivate-app");

    const off = await request(app)
      .patch(`/clients/${client.id}`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ isActive: false });
    expect(off.status).toBe(200);
    expect(off.body.isActive).toBe(false);

    const blocked = await probeSecret(client.clientId, client.clientSecret);
    expect(blocked.body.code).toBe("INVALID_CLIENT");

    const on = await request(app)
      .patch(`/clients/${client.id}`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ isActive: true });
    expect(on.body.isActive).toBe(true);

    const allowed = await probeSecret(client.clientId, client.clientSecret);
    expect(allowed.body.code).toBe("INVALID_CREDENTIALS");
  });

  it("requires the admin key", async () => {
    const client = await createTestClient("lifecycle-guard-app");

    const rotate = await request(app).post(`/clients/${client.id}/rotate-secret`);
    expect(rotate.status).toBe(403);

    const patch = await request(app)
      .patch(`/clients/${client.id}`)
      .send({ isActive: false });
    expect(patch.status).toBe(403);
  });

  it("404s on unknown client ids", async () => {
    const res = await request(app)
      .post("/clients/00000000-0000-0000-0000-000000000000/rotate-secret")
      .set("X-Admin-Key", ADMIN_KEY);
    expect(res.status).toBe(404);
  });
});
