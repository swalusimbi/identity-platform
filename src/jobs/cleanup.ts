import { db } from "../db";
import { refreshTokens, accountTokens, auditLogs } from "../db/schema";
import { lt } from "drizzle-orm";
import { env } from "../utils/env";

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
 * Delete account tokens (password reset, email verification) that
 * expired more than RETENTION_DAYS ago. They are single use and short
 * lived, the retention only aids debugging.
 */
export async function cleanupExpiredAccountTokens(): Promise<number> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);

  const deleted = await db
    .delete(accountTokens)
    .where(lt(accountTokens.expiresAt, cutoff))
    .returning({ id: accountTokens.id });

  return deleted.length;
}

/**
 * Delete audit rows older than the retention window
 * (AUDIT_RETENTION_DAYS, default 365). Inside the window the table is
 * append only, this is the single sanctioned delete path.
 */
export async function cleanupExpiredAuditLogs(): Promise<number> {
  const cutoff = new Date(
    Date.now() - env.AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000
  );

  const deleted = await db
    .delete(auditLogs)
    .where(lt(auditLogs.createdAt, cutoff))
    .returning({ id: auditLogs.id });

  return deleted.length;
}

/**
 * Run the cleanup now and then once a day. The timer is unref'd so it
 * never keeps the process alive on shutdown.
 */
export function scheduleRefreshTokenCleanup(): void {
  const run = async () => {
    try {
      const refresh = await cleanupExpiredRefreshTokens();
      const account = await cleanupExpiredAccountTokens();
      const auditRows = await cleanupExpiredAuditLogs();
      const total = refresh + account + auditRows;
      if (total > 0) console.log(`✓ Removed ${total} stale rows`);
    } catch (err) {
      console.error("Token cleanup failed:", err);
    }
  };

  run();
  setInterval(run, RUN_INTERVAL_MS).unref();
}
