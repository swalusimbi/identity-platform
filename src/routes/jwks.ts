import { Router, Request, Response } from "express";
import { getPublicJwk } from "../services/token";

const router = Router();

router.get("/.well-known/jwks.json", async (_req: Request, res: Response) => {
  try {
    const jwk = await getPublicJwk();

    res
      .set("Cache-Control", "public, max-age=300, stale-while-revalidate=86400")
      .json({ keys: [jwk] });
  } catch {
    res.status(503).json({
      error: "JWKS is not configured",
      code: "JWKS_NOT_CONFIGURED",
    });
  }
});

export default router;
