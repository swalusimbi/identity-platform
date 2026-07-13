import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import app from "../src/app";
import { sentMails } from "../src/services/mailer";
import { createTestClient, uniqueIp } from "./helpers";

const ADMIN_KEY = process.env.ADMIN_KEY!;

function lastMailToken(): string {
  const mail = sentMails[sentMails.length - 1];
  expect(mail).toBeTruthy();
  const match = mail.text.match(/[?&]token=([A-Za-z0-9_-]+)/);
  expect(match).toBeTruthy();
  return match![1];
}

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
    // But it does say what kind of client this is
    expect(created.isPublic).toBe(false);
  });
});

describe("client lifecycle (admin)", () => {
  // Login with an unknown email: INVALID_CLIENT means the secret was
  // rejected, INVALID_CREDENTIALS means it was accepted
  const probeSecret = (clientId: string, clientSecret: string | undefined) =>
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

describe("registration control and tenant bootstrap", () => {
  beforeEach(() => {
    sentMails.length = 0;
  });

  it("closes /auth/register for invite-only clients", async () => {
    const closed = await createTestClient("invite-only-app", {
      allowUserRegistration: false,
    });

    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "stranger@example.com",
        password: "password-123",
        clientId: closed.clientId,
        clientSecret: closed.clientSecret,
      });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe("REGISTRATION_DISABLED");
  });

  it("reopens registration via PATCH", async () => {
    const client = await createTestClient("reopen-app", {
      allowUserRegistration: false,
    });

    await request(app)
      .patch(`/clients/${client.id}`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ allowUserRegistration: true });

    const res = await request(app)
      .post("/auth/register")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "welcome@example.com",
        password: "password-123",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(res.status).toBe(201);
  });

  it("bootstraps a tenant: role, permissions and invited admin", async () => {
    const client = await createTestClient("hospital-app", {
      isPublic: true,
      allowUserRegistration: false,
      passwordResetUrl: "https://hospital.example.com/set-password",
    });

    const res = await request(app)
      .post(`/clients/${client.id}/bootstrap`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ adminEmail: "Admin@Hospital.example.com" });

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe("admin@hospital.example.com");
    expect(res.body.role.name).toBe("admin");
    expect(res.body.permissions).toContain("users:write");

    // The invite email carries a set-password link
    expect(sentMails).toHaveLength(1);
    expect(sentMails[0].to).toBe("admin@hospital.example.com");
    expect(sentMails[0].text).toContain(
      "https://hospital.example.com/set-password?token="
    );

    // Complete the invite: set password, log in, check permissions
    const setPw = await request(app)
      .post("/auth/password/reset")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        token: lastMailToken(),
        newPassword: "admin-first-password",
        clientId: client.clientId,
      });
    expect(setPw.status).toBe(200);

    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "admin@hospital.example.com",
        password: "admin-first-password",
        clientId: client.clientId,
      });
    expect(login.status).toBe(200);

    const verify = await request(app)
      .post("/auth/verify")
      .send({ token: login.body.accessToken, audience: client.clientId });
    expect(verify.body.user.permissions).toContain("users:write");
    expect(verify.body.user.permissions).toContain("api-keys:write");
  });

  it("requires a registered reset page before bootstrapping", async () => {
    const bare = await createTestClient("bootstrap-bare-app");
    const res = await request(app)
      .post(`/clients/${bare.id}/bootstrap`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ adminEmail: "admin@example.com" });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("RESET_URL_NOT_CONFIGURED");
  });

  it("rejects bootstrap when the email is taken", async () => {
    const client = await createTestClient("bootstrap-dup-app", {
      passwordResetUrl: "https://dup.example.com/set-password",
    });

    const first = await request(app)
      .post(`/clients/${client.id}/bootstrap`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ adminEmail: "dup@example.com" });
    expect(first.status).toBe(201);

    const second = await request(app)
      .post(`/clients/${client.id}/bootstrap`)
      .set("X-Admin-Key", ADMIN_KEY)
      .send({ adminEmail: "dup@example.com" });
    expect(second.status).toBe(409);
  });
});
