import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import express from "express";
import http, { Server } from "http";
import type { AddressInfo } from "net";
import request from "supertest";
import { SignJWT, importPKCS8 } from "jose";
import app from "../src/app";
import { createAuthClient, AuthClient } from "../sdk/auth-client";
import { createTestClient, registerTestUser, TestClient, TestUser } from "./helpers";

/**
 * RF-04: requireAuth may only contact the platform for legacy HS256
 * tokens or when JWKS is unavailable. Everything else must be decided
 * locally. The platform sits behind a counting proxy so every test
 * asserts exactly how many /auth/verify calls its scenario caused.
 */

let platform: Server;
let proxy: Server;
let proxyUrl: string;
let verifyCalls = 0;
let jwksDown = false;

let client: TestClient;
let user: TestUser;
let sdk: AuthClient;

const issuer = () => new URL(process.env.SERVICE_URL!).hostname;

function normalizePem(value: string): string {
  return value.replace(/\\n/g, "\n").trim();
}

/** Protected app under test, using the SDK middleware */
function protectedApp(instance: AuthClient) {
  const consumer = express();
  consumer.get("/private", instance.requireAuth, (req, res) => {
    res.json({ email: req.user!.email });
  });
  return consumer;
}

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    platform = app.listen(0, "127.0.0.1", resolve);
  });
  const platformPort = (platform.address() as AddressInfo).port;

  // Counting proxy: forwards everything to the platform, can break JWKS
  proxy = http.createServer(async (req, res) => {
    if (req.url === "/auth/verify") verifyCalls += 1;

    if (jwksDown && req.url === "/.well-known/jwks.json") {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "jwks unavailable" }));
      return;
    }

    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const upstream = await fetch(`http://127.0.0.1:${platformPort}${req.url}`, {
      method: req.method,
      headers: { "Content-Type": req.headers["content-type"] ?? "application/json" },
      body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
    });
    res.writeHead(upstream.status, { "Content-Type": "application/json" });
    res.end(Buffer.from(await upstream.arrayBuffer()));
  });
  await new Promise<void>((resolve) => {
    proxy.listen(0, "127.0.0.1", resolve);
  });
  proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;

  client = await createTestClient("fallback-app");
  user = await registerTestUser(client, "fallback-user@example.com");

  sdk = createAuthClient({
    serviceUrl: proxyUrl,
    issuer: issuer(),
    clientId: client.clientId,
    clientSecret: client.clientSecret,
  });

  // Warm the JWKS cache so later tests measure fallback decisions,
  // not cold cache fetches
  await sdk.verifyTokenLocally(user.accessToken);
});

afterAll(() => {
  platform?.close();
  proxy?.close();
});

beforeEach(() => {
  verifyCalls = 0;
  jwksDown = false;
});

describe("definitive local failures never reach the platform", () => {
  it("expired token: 401 and zero verify calls", async () => {
    const key = await importPKCS8(
      normalizePem(process.env.JWT_PRIVATE_KEY!),
      "EdDSA"
    );
    const expired = await new SignJWT({
      sub: user.id,
      cid: client.id,
      email: user.email,
      permissions: [],
    })
      .setProtectedHeader({ alg: "EdDSA", kid: process.env.JWT_KEY_ID! })
      .setIssuer(issuer())
      .setAudience(client.clientId)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(key);

    const res = await request(protectedApp(sdk))
      .get("/private")
      .set("Authorization", `Bearer ${expired}`);

    expect(res.status).toBe(401);
    expect(verifyCalls).toBe(0);
  });

  it("wrong audience: 401 and zero verify calls", async () => {
    const other = await createTestClient("fallback-other-app");
    const outsider = await registerTestUser(other, "fallback-outsider@example.com");

    const res = await request(protectedApp(sdk))
      .get("/private")
      .set("Authorization", `Bearer ${outsider.accessToken}`);

    expect(res.status).toBe(401);
    expect(verifyCalls).toBe(0);
  });

  it("wrong issuer: 401 and zero verify calls", async () => {
    const foreign = createAuthClient({
      serviceUrl: proxyUrl,
      issuer: "iam.someone-else.example.com",
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    // Warm its JWKS cache so the failure is the issuer, not transport
    await foreign.verifyTokenLocally(user.accessToken).catch(() => {});
    verifyCalls = 0;

    const res = await request(protectedApp(foreign))
      .get("/private")
      .set("Authorization", `Bearer ${user.accessToken}`);

    expect(res.status).toBe(401);
    expect(verifyCalls).toBe(0);
  });

  it("tampered signature: 401 and zero verify calls", async () => {
    const [h, p, s] = user.accessToken.split(".");
    const tampered = `${h}.${p}.${s.slice(0, -4)}${s.slice(-4) === "AAAA" ? "BBBB" : "AAAA"}`;

    const res = await request(protectedApp(sdk))
      .get("/private")
      .set("Authorization", `Bearer ${tampered}`);

    expect(res.status).toBe(401);
    expect(verifyCalls).toBe(0);
  });

  it("malformed token: 401 and zero verify calls", async () => {
    const res = await request(protectedApp(sdk))
      .get("/private")
      .set("Authorization", "Bearer not-even-a-jwt");

    expect(res.status).toBe(401);
    expect(verifyCalls).toBe(0);
  });
});

describe("the two sanctioned fallback paths", () => {
  it("legacy HS256 token: verified remotely, exactly one verify call", async () => {
    const legacyKey = new TextEncoder().encode(process.env.JWT_SECRET!);
    const legacy = await new SignJWT({
      sub: user.id,
      cid: client.id,
      email: user.email,
      permissions: ["legacy:read"],
    })
      .setProtectedHeader({ alg: "HS256", kid: "legacy-hs256" })
      .setIssuer(issuer())
      .setAudience(client.clientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(legacyKey);

    const res = await request(protectedApp(sdk))
      .get("/private")
      .set("Authorization", `Bearer ${legacy}`);

    expect(res.status).toBe(200);
    expect(res.body.email).toBe(user.email);
    expect(verifyCalls).toBe(1);
  });

  it("JWKS outage: valid token verified remotely, exactly one verify call", async () => {
    // Fresh client so its JWKS cache is cold when the outage hits
    const coldSdk = createAuthClient({
      serviceUrl: proxyUrl,
      issuer: issuer(),
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });
    jwksDown = true;

    const res = await request(protectedApp(coldSdk))
      .get("/private")
      .set("Authorization", `Bearer ${user.accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.email).toBe(user.email);
    expect(verifyCalls).toBe(1);
  });
});
