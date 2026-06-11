import { db } from "../db";
import { refreshTokens } from "../db/schema";
import { lt } from "drizzle-orm";

// Rows are kept this long past expiry. Revoked but unexpired rows must
// stay, replay detection on /auth/refresh depends on finding them.
const RETENTION_DAYS = 30;
const RUN_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Delete refresh tokens that expired more than RETENTION_DAYS ago.
 * Returns the number of rows removed.
 */
export async function cleanupExpiredRefreshTokens(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);

  const deleted = await db
    .delete(refreshTokens)
    .where(lt(refreshTokens.expiresAt, cutoff))
    .returning({ id: refreshTokens.id });

  return deleted.length;
}

/**
 * Run the cleanup now and then once a day. The timer is unref'd so it
 * never keeps the process alive on shutdown.
 */
export function scheduleRefreshTokenCleanup(): void {
  const run = () =>
    cleanupExpiredRefreshTokens()
      .then((count) => {
        if (count > 0) console.log(`✓ Removed ${count} stale refresh tokens`);
      })
      .catch((err) => console.error("Refresh token cleanup failed:", err));

  run();
  setInterval(run, RUN_INTERVAL_MS).unref();
}
