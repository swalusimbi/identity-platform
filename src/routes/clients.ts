import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { clients } from "../db/schema";
import { randomBytes, createHash, timingSafeEqual } from "crypto";
import { eq } from "drizzle-orm";
import { AppError } from "../utils/errors";
import { env } from "../utils/env";

const router = Router();

/** Constant time comparison, hashing first to equalize lengths */
function requireAdminKey(provided: unknown): void {
  const expected = createHash("sha256").update(env.ADMIN_KEY).digest();
  const actual = createHash("sha256")
    .update(typeof provided === "string" ? provided : "")
    .digest();

  if (!timingSafeEqual(expected, actual)) {
    throw AppError.forbidden("Invalid admin key");
  }
}

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
  requireAdminKey(req.headers["x-admin-key"]);

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

// POST /clients/:id/rotate-secret — replace a client's secret (admin)
router.post("/:id/rotate-secret", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);
  const id = z.string().uuid().parse(req.params.id);

  const clientSecret = `cs_${randomBytes(32).toString("base64url")}`;
  const clientSecretHash = createHash("sha256")
    .update(clientSecret)
    .digest("hex");

  const [client] = await db
    .update(clients)
    .set({ clientSecretHash, updatedAt: new Date() })
    .where(eq(clients.id, id))
    .returning({ id: clients.id, name: clients.name, clientId: clients.clientId });

  if (!client) throw AppError.notFound("Client not found");

  // The old secret stops working immediately
  res.json({
    ...client,
    clientSecret,
    warning: "Store the client secret securely. It cannot be retrieved again.",
  });
});

// PATCH /clients/:id — update name, redirect URIs or active state (admin)
router.patch("/:id", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);
  const id = z.string().uuid().parse(req.params.id);

  const body = z
    .object({
      name: z.string().min(1).max(255).optional(),
      redirectUris: z.array(z.string().url()).optional(),
      isActive: z.boolean().optional(),
    })
    .refine((v) => Object.keys(v).length > 0, "No fields to update")
    .parse(req.body);

  const [client] = await db
    .update(clients)
    .set({ ...body, updatedAt: new Date() })
    .where(eq(clients.id, id))
    .returning({
      id: clients.id,
      name: clients.name,
      clientId: clients.clientId,
      redirectUris: clients.redirectUris,
      isActive: clients.isActive,
    });

  if (!client) throw AppError.notFound("Client not found");
  res.json(client);
});

// GET /clients — list registered clients (admin)
router.get("/", async (req: Request, res: Response) => {
  requireAdminKey(req.headers["x-admin-key"]);

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
