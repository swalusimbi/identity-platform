/**
 * Runs once before the whole suite (in its own process):
 *   1. Pushes the drizzle schema to the test database
 *   2. Truncates all tables
 *   3. Flushes the test Redis DB (auth codes, rate limit counters)
 *
 * Requires .env.test — see .env.test.example
 */
import { execSync } from "child_process";
import { config } from "dotenv";
import { resolve } from "path";
import postgres from "postgres";
import Redis from "ioredis";

export default async function globalSetup() {
  config({ path: resolve(__dirname, "../.env.test"), override: true });

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl || !/test/.test(databaseUrl)) {
    throw new Error(
      "DATABASE_URL in .env.test must point at a database with 'test' in its name"
    );
  }

  execSync("npx drizzle-kit push --force", {
    cwd: resolve(__dirname, ".."),
    env: process.env,
    stdio: "pipe",
  });

  const sql = postgres(databaseUrl, { max: 1 });
  await sql`
    TRUNCATE TABLE
      service_account_roles, user_roles, role_permissions, refresh_tokens,
      api_keys, service_accounts,
      users, roles, permissions, clients, audit_logs
    CASCADE
  `;
  await sql.end();

  const redis = new Redis(process.env.REDIS_URL!);
  await redis.flushdb();
  redis.disconnect();
}
