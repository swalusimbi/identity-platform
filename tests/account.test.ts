import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";
import app from "../src/app";
import { db } from "../src/db";
import { users } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { sentMails } from "../src/services/mailer";
import {
  createTestClient,
  refreshOperationId,
  registerTestUser,
  uniqueIp,
  TestClient,
} from "./helpers";

function lastMailToken(): string {
  const mail = sentMails[sentMails.length - 1];
  expect(mail).toBeTruthy();
  const match = mail.text.match(/[?&]token=([A-Za-z0-9_-]+)/);
  expect(match).toBeTruthy();
  return match![1];
}

const RESET_URL = "https://app.example.com/reset-password";
const VERIFY_URL = "https://app.example.com/verify-email";

describe("password reset", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("pw-reset-app", {
      passwordResetUrl: RESET_URL,
    });
  });

  beforeEach(() => {
    sentMails.length = 0;
  });

  const forgot = (email: string, c: TestClient = client) =>
    request(app)
      .post("/auth/password/forgot")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email,
        clientId: c.clientId,
        clientSecret: c.clientSecret,
      });

  const reset = (token: string, newPassword: string, c: TestClient = client) =>
    request(app)
      .post("/auth/password/reset")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        token,
        newPassword,
        clientId: c.clientId,
        clientSecret: c.clientSecret,
      });

  const login = (email: string, password: string, c: TestClient = client) =>
    request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email,
        password,
        clientId: c.clientId,
        clientSecret: c.clientSecret,
      });

  it("emails a reset link and resets the password", async () => {
    const user = await registerTestUser(client, "reset-me@example.com");

    const res = await forgot(user.email);
    expect(res.status).toBe(200);
    expect(sentMails).toHaveLength(1);
    expect(sentMails[0].to).toBe(user.email);
    expect(sentMails[0].text).toContain(`${RESET_URL}?token=`);

    const resetRes = await reset(lastMailToken(), "brand-new-password");
    expect(resetRes.status).toBe(200);

    // Old password dead, new one works
    expect((await login(user.email, user.password)).status).toBe(401);
    expect((await login(user.email, "brand-new-password")).status).toBe(200);

    // Resetting proves mailbox control
    const [row] = await db.select().from(users).where(eq(users.id, user.id));
    expect(row.emailVerified).toBe(true);
  });

  it("revokes all sessions on reset", async () => {
    const user = await registerTestUser(client, "reset-revoke@example.com");

    await forgot(user.email);
    await reset(lastMailToken(), "another-new-password");

    const refresh = await request(app).post("/auth/refresh").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      operationId: refreshOperationId(),
    });
    expect(refresh.status).toBe(401);
  });

  it("does not reveal whether an email exists", async () => {
    const res = await forgot("nobody-here@example.com");
    expect(res.status).toBe(200);
    expect(sentMails).toHaveLength(0);
  });

  it("rejects token reuse", async () => {
    const user = await registerTestUser(client, "reset-reuse@example.com");
    await forgot(user.email);
    const token = lastMailToken();

    expect((await reset(token, "first-new-password")).status).toBe(200);
    const second = await reset(token, "second-new-password");
    expect(second.status).toBe(401);
    expect(second.body.code).toBe("INVALID_RESET_TOKEN");
  });

  it("rejects a token presented by a different client", async () => {
    const user = await registerTestUser(client, "reset-cross@example.com");
    await forgot(user.email);
    const token = lastMailToken();

    const other = await createTestClient("pw-reset-other-app");
    const res = await reset(token, "stolen-password", other);
    expect(res.status).toBe(401);
  });

  it("does not consume a reset token presented by a different client", async () => {
    const user = await registerTestUser(client, "reset-cross-keep@example.com");
    await forgot(user.email);
    const token = lastMailToken();

    const publicClient = await createTestClient("pw-reset-public-other-app", {
      isPublic: true,
    });
    const wrongClient = await reset(token, "stolen-password", publicClient);
    expect(wrongClient.status).toBe(401);

    const rightfulClient = await reset(token, "rightful-new-password");
    expect(rightfulClient.status).toBe(200);
    expect((await login(user.email, "rightful-new-password")).status).toBe(200);
  });

  it("rejects forgot requests for clients without a registered reset page", async () => {
    const bare = await createTestClient("pw-reset-bare-app");
    const res = await forgot("whoever@example.com", bare);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("RESET_URL_NOT_CONFIGURED");
    expect(sentMails).toHaveLength(0);
  });

  it("rejects garbage tokens", async () => {
    expect((await reset("not-a-token", "whatever-password")).status).toBe(401);
  });
});

describe("email verification", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("verify-email-app", {
      emailVerifyUrl: VERIFY_URL,
    });
  });

  beforeEach(() => {
    sentMails.length = 0;
  });

  it("sends a link and verifies the email", async () => {
    const user = await registerTestUser(client, "unverified@example.com");

    const sendRes = await request(app)
      .post("/auth/email/send-verification")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(sendRes.status).toBe(200);
    expect(sentMails).toHaveLength(1);
    expect(sentMails[0].text).toContain(`${VERIFY_URL}?token=`);

    const verifyRes = await request(app).post("/auth/email/verify").send({
      token: lastMailToken(),
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(verifyRes.status).toBe(200);

    const [row] = await db.select().from(users).where(eq(users.id, user.id));
    expect(row.emailVerified).toBe(true);
  });

  it("does not send to an already verified email", async () => {
    const user = await registerTestUser(client, "already-verified@example.com");
    await db
      .update(users)
      .set({ emailVerified: true })
      .where(eq(users.id, user.id));

    const res = await request(app)
      .post("/auth/email/send-verification")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(res.status).toBe(200);
    expect(sentMails).toHaveLength(0);
  });

  it("rejects an invalid token", async () => {
    const res = await request(app).post("/auth/email/verify").send({
      token: "bogus",
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_VERIFY_TOKEN");
  });

  it("does not consume a verification token presented by a different client", async () => {
    const user = await registerTestUser(client, "verify-cross-keep@example.com");

    const sendRes = await request(app)
      .post("/auth/email/send-verification")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(sendRes.status).toBe(200);
    const token = lastMailToken();

    const publicClient = await createTestClient("verify-public-other-app", {
      isPublic: true,
    });
    const wrongClient = await request(app).post("/auth/email/verify").send({
      token,
      clientId: publicClient.clientId,
    });
    expect(wrongClient.status).toBe(401);

    const rightfulClient = await request(app).post("/auth/email/verify").send({
      token,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    expect(rightfulClient.status).toBe(200);

    const [row] = await db.select().from(users).where(eq(users.id, user.id));
    expect(row.emailVerified).toBe(true);
  });
});

describe("password change", () => {
  let client: TestClient;

  beforeAll(async () => {
    client = await createTestClient("pw-change-app");
  });

  it("changes the password and revokes other sessions", async () => {
    const user = await registerTestUser(client, "changer@example.com");

    const res = await request(app)
      .post("/auth/password/change")
      .set("Authorization", `Bearer ${user.accessToken}`)
      .send({
        currentPassword: user.password,
        newPassword: "my-changed-password",
      });
    expect(res.status).toBe(200);

    // Old refresh token revoked
    const refresh = await request(app).post("/auth/refresh").send({
      refreshToken: user.refreshToken,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      operationId: refreshOperationId(),
    });
    expect(refresh.status).toBe(401);

    // New password works
    const login = await request(app)
      .post("/auth/login")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        password: "my-changed-password",
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });
    expect(login.status).toBe(200);
  });

  it("rejects a wrong current password", async () => {
    const user = await registerTestUser(client, "wrong-current@example.com");

    const res = await request(app)
      .post("/auth/password/change")
      .set("Authorization", `Bearer ${user.accessToken}`)
      .send({
        currentPassword: "not-my-password",
        newPassword: "irrelevant-password",
      });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CREDENTIALS");
  });

  it("requires authentication", async () => {
    const res = await request(app).post("/auth/password/change").send({
      currentPassword: "x",
      newPassword: "long-enough-password",
    });
    expect(res.status).toBe(401);
  });
});
