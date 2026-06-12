import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";
import app from "../src/app";
import { sentMails } from "../src/services/mailer";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  uniqueIp,
  TestClient,
  TestUser,
} from "./helpers";

const SET_PASSWORD_URL = "https://staff.example.com/set-password";

function lastMailToken(): string {
  const mail = sentMails[sentMails.length - 1];
  expect(mail).toBeTruthy();
  const match = mail.text.match(/[?&]token=([A-Za-z0-9_-]+)/);
  expect(match).toBeTruthy();
  return match![1];
}

describe("user management API", () => {
  let client: TestClient;
  let admin: TestUser;

  beforeAll(async () => {
    client = await createTestClient("staff-app", {
      passwordResetUrl: SET_PASSWORD_URL,
    });
    await seedDefaultRole(client.id, [
      { resource: "users", action: "read" },
      { resource: "users", action: "write" },
      { resource: "api-keys", action: "write" },
    ]);
    admin = await registerTestUser(client, "staff-admin@example.com");
  });

  beforeEach(() => {
    sentMails.length = 0;
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  it("provisions a user and the invite link sets their password", async () => {
    const res = await request(app)
      .post("/users")
      .set(auth(admin.accessToken))
      .send({ email: "Nurse.Joy@Example.com" });

    expect(res.status).toBe(201);
    expect(res.body.email).toBe("nurse.joy@example.com");
    expect(res.body.id).toBeTruthy(); // consumers create memberships from this
    expect(res.body.invited).toBe(true);

    expect(sentMails).toHaveLength(1);
    expect(sentMails[0].to).toBe("nurse.joy@example.com");
    expect(sentMails[0].text).toContain(`${SET_PASSWORD_URL}?token=`);

    const setPw = await request(app)
      .post("/auth/password/reset")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        token: lastMailToken(),
        newPassword: "nurse-password-1",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(setPw.status).toBe(200);

    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: "nurse.joy@example.com",
        password: "nurse-password-1",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(login.status).toBe(200);
  });

  it("can provision without an invite", async () => {
    const res = await request(app)
      .post("/users")
      .set(auth(admin.accessToken))
      .send({ email: "oauth-only@example.com", sendInvite: false });

    expect(res.status).toBe(201);
    expect(res.body.invited).toBe(false);
    expect(sentMails).toHaveLength(0);
  });

  it("rejects duplicate emails", async () => {
    const res = await request(app)
      .post("/users")
      .set(auth(admin.accessToken))
      .send({ email: "staff-admin@example.com" });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("EMAIL_EXISTS");
  });

  it("rejects roles belonging to another client", async () => {
    const other = await createTestClient("staff-foreign-app");
    await seedDefaultRole(other.id, [
      { resource: "foreign", action: "read" },
    ], "foreign-role");

    // Grab the foreign role id straight from the other tenant's seed
    const { db } = await import("../src/db");
    const { roles } = await import("../src/db/schema");
    const { eq } = await import("drizzle-orm");
    const [foreignRole] = await db
      .select({ id: roles.id })
      .from(roles)
      .where(eq(roles.clientId, other.id));

    const res = await request(app)
      .post("/users")
      .set(auth(admin.accessToken))
      .send({ email: "sneaky@example.com", roleIds: [foreignRole.id] });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("UNKNOWN_ROLE");
  });

  it("lists only the client's users", async () => {
    const res = await request(app).get("/users").set(auth(admin.accessToken));

    expect(res.status).toBe(200);
    const emails = res.body.map((u: { email: string }) => u.email);
    expect(emails).toContain("staff-admin@example.com");
    expect(emails).toContain("nurse.joy@example.com");
    expect(emails).not.toContain("sneaky@example.com"); // creation failed
    expect(res.body[0].passwordHash).toBeUndefined();
  });

  it("deactivates a user: login blocked, sessions revoked", async () => {
    const member = await registerTestUser(client, "leaver@example.com");

    const res = await request(app)
      .patch(`/users/${member.id}`)
      .set(auth(admin.accessToken))
      .send({ isActive: false });
    expect(res.status).toBe(200);
    expect(res.body.isActive).toBe(false);

    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: member.email,
        password: member.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(login.status).toBe(401);

    const refresh = await request(app).post("/auth/refresh").send({
      refreshToken: member.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(refresh.status).toBe(401);

    // Reactivation restores access
    await request(app)
      .patch(`/users/${member.id}`)
      .set(auth(admin.accessToken))
      .send({ isActive: true });

    const back = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: member.email,
        password: member.password,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(back.status).toBe(200);
  });

  it("provisions through an API key, the server-to-server pattern", async () => {
    const keyRes = await request(app)
      .post("/api-keys")
      .set(auth(admin.accessToken))
      .send({ name: "provisioning-key", scopes: ["users:write"] });
    expect(keyRes.status).toBe(201);

    const res = await request(app)
      .post("/users")
      .set("Authorization", `ApiKey ${keyRes.body.key}`)
      .send({ email: "via-api-key@example.com" });

    expect(res.status).toBe(201);
    expect(sentMails).toHaveLength(1);
  });

  it("requires users:write to provision", async () => {
    const other = await createTestClient("staff-unpriv-app");
    const peon = await registerTestUser(other, "staff-peon@example.com");

    const res = await request(app)
      .post("/users")
      .set(auth(peon.accessToken))
      .send({ email: "nope@example.com" });
    expect(res.status).toBe(403);
  });

  it("requires authentication", async () => {
    const res = await request(app).get("/users");
    expect(res.status).toBe(401);
  });
});
