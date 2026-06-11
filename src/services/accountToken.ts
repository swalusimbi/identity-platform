import { randomBytes } from "crypto";
import { db } from "../db";
import { accountTokens } from "../db/schema";
import { and, eq, isNull, gt } from "drizzle-orm";
import { hashToken } from "./token";

export type AccountTokenPurpose = "password_reset" | "email_verify";

const TTL_HOURS: Record<AccountTokenPurpose, number> = {
  password_reset: 1,
  email_verify: 24,
};

/**
 * Issue a single-use token for the given purpose. The raw token goes
 * into the email link, only its hash is stored.
 */
export async function createAccountToken(
  userId: string,
  purpose: AccountTokenPurpose
): Promise<string> {
  const token = randomBytes(32).toString("base64url");

  await db.insert(accountTokens).values({
    userId,
    purpose,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + TTL_HOURS[purpose] * 60 * 60 * 1000),
  });

  return token;
}

/**
 * Atomically consume a token: marks it used and returns the owning
 * user id, or null when unknown, expired, used or the wrong purpose.
 */
export async function consumeAccountToken(
  token: string,
  purpose: AccountTokenPurpose
): Promise<{ userId: string } | null> {
  const now = new Date();

  const [consumed] = await db
    .update(accountTokens)
    .set({ usedAt: now })
    .where(
      and(
        eq(accountTokens.tokenHash, hashToken(token)),
        eq(accountTokens.purpose, purpose),
        isNull(accountTokens.usedAt),
        gt(accountTokens.expiresAt, now)
      )
    )
    .returning({ userId: accountTokens.userId });

  return consumed ?? null;
}
