import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { clients } from "../db/schema";
import { randomBytes, createHash } from "crypto";
import { eq } from "drizzle-orm";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

const router = Router();

const createClientSchema = z.object({
  name: z.string().min(1).max(255),
  redirectUris: z.array(z.string().url()).optional(),
});

/**
 * POST /clients — register a new app client
 *
 * This is an admin-only endpoint. In production, protect it with
 * a master API key or restrict to localhost.
 *
 * For now: accessible via a shared secret header (X-Admin-Key)
 * that you set in the environment. Simple, effective for a single-operator setup.
 */
router.post("/", async (req: Request, res: Response) => {
  const adminKey = req.headers["x-admin-key"];
  if (!adminKey || adminKey !== env.ADMIN_KEY) {
    throw AppError.forbidden("Invalid admin key");
  }

  const body = createClientSchema.parse(req.body);

  // Generate client credentials
  const clientId = `cl_${randomBytes(16).toString("base64url")}`;
  const clientSecret = `cs_${randomBytes(32).toString("base64url")}`;
  const clientSecretHash = createHash("sha256")
    .update(clientSecret)
    .digest("hex");

  const [client] = await db
    .insert(clients)
    .values({
      name: body.name,
      clientId,
      clientSecretHash,
      redirectUris: body.redirectUris || [],
    })
    .returning({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      createdAt: clients.createdAt,
    });

  // Return secret ONCE
  res.status(201).json({
    ...client,
    clientSecret, // ← Only time this is visible
    warning: "Store the client secret securely. It cannot be retrieved again.",
  });
});

// GET /clients — list registered clients (admin)
router.get("/", async (req: Request, res: Response) => {
  const adminKey = req.headers["x-admin-key"];
  if (!adminKey || adminKey !== env.ADMIN_KEY) {
    throw AppError.forbidden("Invalid admin key");
  }

  const all = await db
    .select({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      isActive: clients.isActive,
      createdAt: clients.createdAt,
    })
    .from(clients);

  res.json(all);
});

export default router;
