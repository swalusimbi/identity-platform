import { describe, it, expect } from "vitest";
import { db } from "../src/db";
import { refreshTokens } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { cleanupExpiredRefreshTokens } from "../src/jobs/cleanup";
import { hashToken } from "../src/services/token";
import { createTestClient, registerTestUser } from "./helpers";

const DAY_MS = 24 * 60 * 60 * 1000;

describe("refresh token cleanup", () => {
  it("removes tokens expired beyond retention and keeps the rest", async () => {
    const client = await createTestClient("cleanup-app");
    const user = await registerTestUser(client, "cleanup@example.com");

    const insert = (name: string, expiresAt: Date, revoked = false) =>
      db.insert(refreshTokens).values({
        userId: user.id,
        tokenHash: hashToken(`cleanup-${name}`),
        expiresAt,
        revoked,
      });

    await insert("ancient", new Date(Date.now() - 31 * DAY_MS));
    await insert("recent-expired", new Date(Date.now() - 1 * DAY_MS));
    await insert("revoked-active", new Date(Date.now() + 5 * DAY_MS), true);

    const removed = await cleanupExpiredRefreshTokens();
    expect(removed).toBeGreaterThanOrEqual(1);

    const remaining = await db
      .select({ tokenHash: refreshTokens.tokenHash })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, user.id));
    const hashes = remaining.map((r) => r.tokenHash);

    // Long-expired row is gone
    expect(hashes).not.toContain(hashToken("cleanup-ancient"));
    // Recently expired row is retained for the retention window
    expect(hashes).toContain(hashToken("cleanup-recent-expired"));
    // Revoked but unexpired row survives, replay detection needs it
    expect(hashes).toContain(hashToken("cleanup-revoked-active"));
  });
});
