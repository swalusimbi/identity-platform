import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import http from "http";
import type { Server } from "http";
import type { AddressInfo } from "net";
import request from "supertest";
import app from "../src/app";
import {
  createAuthClient,
  requirePermission,
  AuthClient,
  AuthApiError,
  AuthTransportError,
  MachinePrincipal,
} from "../sdk/auth-client";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  TestClient,
  TestUser,
} from "./helpers";

let server: Server;
let serviceUrl: string;
let client: TestClient;
let admin: TestUser;
let sdk: AuthClient;
let plainKey: string;
let serviceAccountKey: string;

const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  serviceUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  client = await createTestClient("sdk-principals-app");
  await seedDefaultRole(client.id, [
    { resource: "roles", action: "write" },
    { resource: "api-keys", action: "write" },
    { resource: "service-accounts", action: "write" },
  ]);
  admin = await registerTestUser(client, "sdk-principals-admin@example.com");

  sdk = createAuthClient({
    serviceUrl,
    issuer: new URL(process.env.SERVICE_URL!).hostname,
    clientId: client.clientId,
    clientSecret: client.clientSecret,
  });

  // A plain scoped key
  const keyRes = await request(app)
    .post("/api-keys")
    .set(auth(admin.accessToken))
    .send({ name: "plain-key", scopes: ["notes:read"] });
  plainKey = keyRes.body.key;

  // A service account with a role carrying notes:purge
  const permRes = await request(app)
    .post("/roles/permissions")
    .set(auth(admin.accessToken))
    .send({ resource: "notes", action: "purge" });
  const roleRes = await request(app)
    .post("/roles")
    .set(auth(admin.accessToken))
    .send({ name: "sdk-machine-role", permissionIds: [permRes.body.id] });
  const saRes = await request(app)
    .post("/service-accounts")
    .set(auth(admin.accessToken))
    .send({ name: "sdk-reporter" });
  await request(app)
    .post(`/service-accounts/${saRes.body.id}/roles`)
    .set(auth(admin.accessToken))
    .send({ roleId: roleRes.body.id });
  const saKeyRes = await request(app)
    .post(`/service-accounts/${saRes.body.id}/api-keys`)
    .set(auth(admin.accessToken))
    .send({ name: "sdk-reporter-key" });
  serviceAccountKey = saKeyRes.body.key;
});

afterAll(() => {
  server?.close();
});

/** A consumer app protecting routes with the SDK middleware */
function consumerApp(instance: AuthClient) {
  const consumer = express();
  consumer.get("/machine", instance.requireApiKey, (req, res) => {
    res.json(req.principal);
  });
  consumer.get(
    "/purge",
    instance.requirePrincipal,
    requirePermission("notes:purge"),
    (req, res) => {
      res.json({ by: req.principal!.kind });
    }
  );
  consumer.get("/who", instance.requirePrincipal, (req, res) => {
    res.json({ kind: req.principal!.kind });
  });
  return consumer;
}

describe("machine principals through the SDK", () => {
  it("authenticates a plain API key and exposes its scopes", async () => {
    const res = await request(consumerApp(sdk))
      .get("/machine")
      .set("Authorization", `ApiKey ${plainKey}`);

    expect(res.status).toBe(200);
    const principal = res.body as MachinePrincipal;
    expect(principal.kind).toBe("api_key");
    expect(principal.permissions).toEqual(["notes:read"]);
    expect(principal.serviceAccountId).toBeUndefined();
  });

  it("authenticates a service account key with resolved role permissions", async () => {
    const res = await request(consumerApp(sdk))
      .get("/machine")
      .set("Authorization", `ApiKey ${serviceAccountKey}`);

    expect(res.status).toBe(200);
    const principal = res.body as MachinePrincipal;
    expect(principal.kind).toBe("service_account");
    expect(principal.serviceAccountName).toBe("sdk-reporter");
    expect(principal.permissions).toContain("notes:purge");
  });

  it("rejects a key belonging to another application", async () => {
    const other = await createTestClient("sdk-principals-other");
    await seedDefaultRole(other.id, [{ resource: "api-keys", action: "write" }]);
    const otherAdmin = await registerTestUser(other, "sdk-p-other@example.com");
    const foreign = await request(app)
      .post("/api-keys")
      .set(auth(otherAdmin.accessToken))
      .send({ name: "foreign-key", scopes: ["*"] });

    const res = await request(consumerApp(sdk))
      .get("/machine")
      .set("Authorization", `ApiKey ${foreign.body.key}`);

    expect(res.status).toBe(401);
  });

  it("requirePermission gates machine principals like users", async () => {
    const allowed = await request(consumerApp(sdk))
      .get("/purge")
      .set("Authorization", `ApiKey ${serviceAccountKey}`);
    expect(allowed.status).toBe(200);
    expect(allowed.body.by).toBe("service_account");

    const denied = await request(consumerApp(sdk))
      .get("/purge")
      .set("Authorization", `ApiKey ${plainKey}`);
    expect(denied.status).toBe(403);
  });

  it("requirePrincipal dispatches on the authorization scheme", async () => {
    const asUser = await request(consumerApp(sdk))
      .get("/who")
      .set(auth(admin.accessToken));
    expect(asUser.body.kind).toBe("user");

    const asMachine = await request(consumerApp(sdk))
      .get("/who")
      .set("Authorization", `ApiKey ${plainKey}`);
    expect(asMachine.body.kind).toBe("api_key");

    const wrongScheme = await request(consumerApp(sdk))
      .get("/who")
      .set("Authorization", "Basic dXNlcjpwYXNz");
    expect(wrongScheme.status).toBe(401);
  });
});

describe("consistent SDK errors", () => {
  it("logout failures throw instead of passing silently", async () => {
    const wrongSecret = createAuthClient({
      serviceUrl,
      issuer: new URL(process.env.SERVICE_URL!).hostname,
      clientId: client.clientId,
      clientSecret: "cs_definitely_wrong",
    });

    await expect(wrongSecret.logout("some-refresh-token")).rejects.toMatchObject({
      name: "AuthApiError",
      status: 401,
      code: "INVALID_CLIENT",
    });
  });

  it("preserves validation details", async () => {
    try {
      await sdk.register("not-an-email", "x");
      expect.unreachable("register should have thrown");
    } catch (err) {
      const apiError = err as AuthApiError;
      expect(apiError).toBeInstanceOf(AuthApiError);
      expect(apiError.status).toBe(400);
      expect(apiError.code).toBe("VALIDATION_ERROR");
      expect(Array.isArray(apiError.details)).toBe(true);
    }
  });

  it("exposes rate limit information on 429", async () => {
    let limited: AuthApiError | undefined;
    for (let i = 0; i < 7; i++) {
      try {
        await sdk.login("sdk-p-limited@example.com", "wrong-password");
      } catch (err) {
        if (err instanceof AuthApiError && err.status === 429) {
          limited = err;
          break;
        }
      }
    }

    expect(limited).toBeDefined();
    expect(limited!.rateLimit?.limit).toBe(5);
    expect(limited!.rateLimit?.resetAt).toBeInstanceOf(Date);
    expect(limited!.rateLimit!.resetAt!.getTime()).toBeGreaterThan(Date.now());
  });
});

describe("transport handling and configuration", () => {
  it("surfaces connection failures as AuthTransportError", async () => {
    const unreachable = createAuthClient({
      serviceUrl: "http://127.0.0.1:1",
      clientId: "cl_unreachable",
    });

    await expect(unreachable.login("a@example.com", "pw")).rejects.toBeInstanceOf(
      AuthTransportError
    );
  });

  it("aborts at the configured timeout", async () => {
    // A server that accepts requests and never answers
    const black = http.createServer(() => {});
    await new Promise<void>((resolve) => black.listen(0, "127.0.0.1", resolve));
    const port = (black.address() as AddressInfo).port;

    const slow = createAuthClient({
      serviceUrl: `http://127.0.0.1:${port}`,
      clientId: "cl_slow",
      requestTimeoutMs: 250,
    });

    const started = Date.now();
    await expect(slow.login("a@example.com", "pw")).rejects.toBeInstanceOf(
      AuthTransportError
    );
    expect(Date.now() - started).toBeLessThan(5_000);
    black.close();
  });

  it("fails fast on missing configuration", () => {
    expect(() => createAuthClient({ serviceUrl: "", clientId: "cl_x" })).toThrow(
      /serviceUrl/
    );
    expect(() =>
      createAuthClient({ serviceUrl: "http://localhost:1", clientId: "" })
    ).toThrow(/clientId/);
  });

  it("normalizes trailing slashes in serviceUrl", () => {
    const slashy = createAuthClient({
      serviceUrl: "https://iam.example.com///",
      clientId: "cl_x",
      redirectUri: "https://app.example.com/cb",
    });
    const url = slashy.getOAuthUrl("google");
    expect(url.startsWith("https://iam.example.com/auth/oauth/google?")).toBe(true);
    expect(url).not.toContain("com//");
  });
});
