import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "http";
import type { AddressInfo } from "net";
import app from "../src/app";
import { createAuthClient, AuthClient, AuthApiError } from "../sdk/auth-client";
import {
  createTestClient,
  registerTestUser,
  seedDefaultRole,
  TestClient,
} from "./helpers";

// The SDK talks over real HTTP, so bind the app to an ephemeral port
let server: Server;
let client: TestClient;
let sdk: AuthClient;

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;

  client = await createTestClient("sdk-app");
  await seedDefaultRole(client.id, [{ resource: "sdk", action: "read" }]);

  // The service signs with its SERVICE_URL hostname, while this test
  // reaches it via 127.0.0.1, so the issuer must be set explicitly
  sdk = createAuthClient({
    serviceUrl: `http://127.0.0.1:${port}`,
    issuer: new URL(process.env.SERVICE_URL!).hostname,
    clientId: client.clientId,
    clientSecret: client.clientSecret,
  });
});

afterAll(() => {
  server?.close();
});

describe("sdk factory", () => {
  it("registers, logs in and verifies tokens locally via JWKS", async () => {
    const registered = await sdk.register("sdk-user@example.com", "password-123");
    expect(registered.user.email).toBe("sdk-user@example.com");

    const session = await sdk.login("sdk-user@example.com", "password-123");
    expect(session.accessToken).toBeTruthy();

    const user = await sdk.verifyTokenLocally(session.accessToken);
    expect(user.email).toBe("sdk-user@example.com");
    expect(user.permissions).toContain("sdk:read");
  });

  it("refreshes and the response carries no user field", async () => {
    const session = await sdk.login("sdk-user@example.com", "password-123");
    const refreshed = await sdk.refreshToken(
      session.refreshToken,
      sdk.createRefreshOperationId()
    );

    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.refreshToken).not.toBe(session.refreshToken);
    expect("user" in refreshed).toBe(false);
  });

  it("recovers an ambiguous refresh with the same operation id", async () => {
    const session = await sdk.register(
      "sdk-refresh-retry@example.com",
      "password-123"
    );
    const operationId = sdk.createRefreshOperationId();

    const first = await sdk.refreshToken(session.refreshToken, operationId);
    const retry = await sdk.refreshToken(session.refreshToken, operationId);

    expect(retry.refreshToken).not.toBe(first.refreshToken);
  });

  it("rejects tokens from a different deployment issuer", async () => {
    const session = await sdk.login("sdk-user@example.com", "password-123");

    const { port } = server.address() as AddressInfo;
    const wrongIssuer = createAuthClient({
      serviceUrl: `http://127.0.0.1:${port}`,
      issuer: "auth.someone-else.com",
      clientId: client.clientId,
      clientSecret: client.clientSecret,
    });

    await expect(
      wrongIssuer.verifyTokenLocally(session.accessToken)
    ).rejects.toThrow();
  });

  it("rejects tokens issued to a different application", async () => {
    const otherClient = await createTestClient("sdk-other-app");
    const otherUser = await registerTestUser(
      otherClient,
      "sdk-other-user@example.com"
    );

    await expect(
      sdk.verifyTokenLocally(otherUser.accessToken)
    ).rejects.toThrow();

    const remote = await sdk.verifyTokenRemote(otherUser.accessToken);
    expect(remote.valid).toBe(false);
  });

  it("surfaces platform errors as exceptions", async () => {
    await expect(sdk.login("sdk-user@example.com", "wrong-password")).rejects.toThrow(
      /invalid credentials/i
    );
  });

  it("preserves the platform's status and code on failures", async () => {
    try {
      await sdk.login("sdk-user@example.com", "wrong-password");
      expect.unreachable("login should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthApiError);
      const apiError = err as AuthApiError;
      expect(apiError.status).toBe(401);
      expect(apiError.code).toBe("INVALID_CREDENTIALS");
      // Still a plain Error for consumers that never look closer
      expect(err).toBeInstanceOf(Error);
    }
  });
});
