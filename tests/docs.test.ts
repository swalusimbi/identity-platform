import { describe, it, expect } from "vitest";
import request from "supertest";
import app from "../src/app";
import { createDocsInitScript } from "../src/routes/docs";

describe("live API docs", () => {
  it("serves the openapi spec", async () => {
    const res = await request(app).get("/openapi.json");

    expect(res.status).toBe(200);
    expect(res.type).toBe("application/json");
    expect(res.body.openapi).toMatch(/^3\.1/);
    expect(res.body.info.title).toBe("Identity Platform API");
    expect(res.body.servers.map((server: { url: string }) => server.url)).toEqual([
      "/",
      "http://localhost:5300",
    ]);
    expect(res.body.externalDocs.url).toBe(
      "https://github.com/swalusimbi/identity-platform/tree/main/docs",
    );
    expect(Object.keys(res.body.paths)).toContain("/auth/login");

    const httpMethods = new Set(["get", "post", "put", "patch", "delete"]);
    const operations = Object.values(res.body.paths).flatMap((path: unknown) =>
      Object.entries(path as Record<string, unknown>)
        .filter(([method]) => httpMethods.has(method))
        .map(([, operation]) => operation as { operationId?: string }),
    );
    const operationIds = operations.map((operation) => operation.operationId);

    expect(operationIds).not.toContain(undefined);
    expect(new Set(operationIds).size).toBe(operations.length);
    expect(res.body.components.schemas.AuthTokenResponse.example).toBeDefined();
    expect(res.body.components.schemas.CreateApiKeyResponse.example).toBeDefined();
    expect(res.body.components.schemas.CreateClientResponse.example).toBeDefined();
  });

  it("serves the docs viewer without inline scripts", async () => {
    const res = await request(app).get("/docs");

    expect(res.status).toBe(200);
    expect(res.type).toBe("text/html");
    expect(res.text).toContain('id="swagger-ui"');
    // helmet's CSP is script-src 'self', so every script must be a file
    expect(res.text).not.toMatch(/<script>[^<]/);
  });

  it("serves the viewer assets and loader", async () => {
    const bundle = await request(app).get("/docs/swagger-ui-bundle.js");
    expect(bundle.status).toBe(200);

    const init = await request(app).get("/docs/init.js");
    expect(init.status).toBe(200);
    expect(init.text).toContain('url: "/openapi.json"');
    expect(init.text).toContain('supportedSubmitMethods: ["get"');
  });

  it("disables request execution in the production viewer", () => {
    const init = createDocsInitScript("production");

    expect(init).toContain("tryItOutEnabled: false");
    expect(init).toContain("supportedSubmitMethods: []");
  });
});
