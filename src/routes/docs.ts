import { Router, Request, Response } from "express";
import express from "express";
import path from "path";

const router = Router();

// The spec ships with the repo and describes the deployed version,
// serving it keeps the running instance self describing
const specPath = path.resolve(process.cwd(), "docs/openapi.json");

// Viewer assets come from the swagger-ui-dist package, served as
// static files. No CDN: the platform stays self contained.
const swaggerUiDir = path.dirname(
  require.resolve("swagger-ui-dist/swagger-ui-bundle.js")
);

// The page and its loader are external files rather than inline
// scripts so helmet's default CSP (script-src 'self') allows them
const DOCS_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Identity Platform API</title>
  <link rel="stylesheet" href="/docs/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/docs/swagger-ui-bundle.js"></script>
  <script src="/docs/init.js"></script>
</body>
</html>
`;

const INIT_SCRIPT = `window.ui = SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  tryItOutEnabled: true,
});
`;

router.get("/openapi.json", (_req: Request, res: Response) => {
  res.set("Cache-Control", "public, max-age=300").sendFile(specPath);
});

router.get("/docs", (_req: Request, res: Response) => {
  res.type("html").send(DOCS_PAGE);
});

router.get("/docs/init.js", (_req: Request, res: Response) => {
  res.type("application/javascript").send(INIT_SCRIPT);
});

router.use("/docs", express.static(swaggerUiDir, { index: false }));

export default router;
