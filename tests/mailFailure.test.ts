import { describe, it, expect, beforeAll, vi } from "vitest";
import request from "supertest";

// A transport whose delivery always fails, standing in for a dead or
// hanging SMTP server. Mocked before the app imports the mailer.
const { sendMailMock, createTransportMock } = vi.hoisted(() => {
  const sendMailMock = vi
    .fn()
    .mockRejectedValue(new Error("connect ETIMEDOUT"));
  const createTransportMock = vi.fn(() => ({ sendMail: sendMailMock }));
  return { sendMailMock, createTransportMock };
});

vi.mock("nodemailer", () => ({
  default: { createTransport: createTransportMock },
}));

import app from "../src/app";
import { env } from "../src/utils/env";
import {
  createTestClient,
  registerTestUser,
  uniqueIp,
  TestClient,
  TestUser,
} from "./helpers";

describe("mail delivery failure", () => {
  let client: TestClient;
  let user: TestUser;

  beforeAll(async () => {
    // This file runs in its own process, safe to flip the provider
    (env as { MAIL_PROVIDER: string }).MAIL_PROVIDER = "smtp";
    (env as { SMTP_URL?: string }).SMTP_URL = "smtp://mail.example.com:587";

    client = await createTestClient("mailfail-app", {
      passwordResetUrl: "https://app.example.com/reset",
    });
    user = await registerTestUser(client, "mailfail-user@example.com");
  });

  it("surfaces SMTP failure on forgot password as a fast 502", async () => {
    const res = await request(app)
      .post("/auth/password/forgot")
      .set("X-Forwarded-For", uniqueIp())
      .send({
        email: user.email,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
      });

    expect(res.status).toBe(502);
    expect(res.body.code).toBe("MAIL_UNAVAILABLE");
    expect(sendMailMock).toHaveBeenCalled();
  });

  it("configures the transport with bounded timeouts", () => {
    expect(createTransportMock).toHaveBeenCalledWith(
      expect.objectContaining({
        connectionTimeout: 10_000,
        greetingTimeout: 10_000,
        socketTimeout: 15_000,
      })
    );
  });
});
