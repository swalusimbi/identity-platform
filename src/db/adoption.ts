import { createHash } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import type postgres from "postgres";

/**
 * Adoption support for databases that predate the migrations journal,
 * typically ones managed with `drizzle-kit push`. Each migration has a
 * marker, a schema object it creates, so the applied prefix can be
 * detected from the live schema and recorded in the journal without
 * rerunning anything. See docs/operations/adopting-an-existing-database.md.
 */

interface MigrationMarker {
  tag: string;
  probe: { table: string; column?: string };
}

// One marker per migration, in journal order. Every new migration
// must add its marker here; the tests fail when one is missing.
export const MIGRATION_MARKERS: MigrationMarker[] = [
  { tag: "0000_known_maria_hill", probe: { table: "clients" } },
  { tag: "0001_clear_fixer", probe: { table: "account_tokens" } },
  { tag: "0002_stormy_steel_serpent", probe: { table: "clients", column: "is_public" } },
  { tag: "0003_stormy_adam_destine", probe: { table: "clients", column: "password_reset_url" } },
  { tag: "0004_odd_cargill", probe: { table: "clients", column: "allow_user_registration" } },
  { tag: "0005_tearful_nightcrawler", probe: { table: "audit_logs" } },
  { tag: "0006_amusing_punisher", probe: { table: "refresh_tokens", column: "revoked_reason" } },
  { tag: "0007_strong_multiple_man", probe: { table: "service_accounts" } },
  { tag: "0008_naive_payback", probe: { table: "refresh_tokens", column: "rotation_operation_hash" } },
];

interface JournalEntry {
  tag: string;
  when: number;
}

export function readJournal(migrationsFolder = "drizzle"): JournalEntry[] {
  const journal = JSON.parse(
    readFileSync(path.join(migrationsFolder, "meta/_journal.json"), "utf8")
  ) as { entries: { tag: string; when: number }[] };
  return journal.entries.map((e) => ({ tag: e.tag, when: e.when }));
}

async function probeExists(
  sql: postgres.Sql,
  probe: MigrationMarker["probe"]
): Promise<boolean> {
  if (probe.column) {
    const rows = await sql`
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = ${probe.table}
        AND column_name = ${probe.column}
      LIMIT 1`;
    return rows.length > 0;
  }
  const rows = await sql`
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = ${probe.table}
    LIMIT 1`;
  return rows.length > 0;
}

export async function journalExists(sql: postgres.Sql): Promise<boolean> {
  const rows = await sql`
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'drizzle' AND table_name = '__drizzle_migrations'
    LIMIT 1`;
  return rows.length > 0;
}

export async function databaseIsPopulated(sql: postgres.Sql): Promise<boolean> {
  return probeExists(sql, { table: "clients" });
}

/**
 * Detect the contiguous prefix of migrations already reflected in the
 * live schema. Throws when the schema matches a later migration but
 * not an earlier one, which no push or migrate history can produce.
 */
export async function detectAppliedMigrations(
  sql: postgres.Sql
): Promise<string[]> {
  const journal = readJournal();
  const known = new Set(MIGRATION_MARKERS.map((m) => m.tag));
  const unmarked = journal.filter((e) => !known.has(e.tag));
  if (unmarked.length > 0) {
    throw new Error(
      `No adoption marker defined for: ${unmarked.map((e) => e.tag).join(", ")}. ` +
        "Add markers to MIGRATION_MARKERS in src/db/adoption.ts."
    );
  }

  const applied: string[] = [];
  let prefixEnded = false;
  for (const marker of MIGRATION_MARKERS) {
    const present = await probeExists(sql, marker.probe);
    if (present && prefixEnded) {
      throw new Error(
        `Schema matches ${marker.tag} but not an earlier migration. ` +
          "This schema does not correspond to any migration prefix, adopt it manually."
      );
    }
    if (!present) prefixEnded = true;
    else applied.push(marker.tag);
  }
  return applied;
}

/**
 * Record the detected migrations as applied. Creates the journal
 * exactly as drizzle would and inserts one row per detected migration
 * with the real file hash and journal timestamp.
 */
export async function baselineJournal(
  sql: postgres.Sql,
  appliedTags: string[],
  migrationsFolder = "drizzle"
): Promise<void> {
  const journal = readJournal(migrationsFolder);

  await sql`CREATE SCHEMA IF NOT EXISTS drizzle`;
  await sql`
    CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (
      id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint
    )`;

  for (const tag of appliedTags) {
    const entry = journal.find((e) => e.tag === tag);
    if (!entry) throw new Error(`Migration ${tag} is not in the journal`);
    const content = readFileSync(
      path.join(migrationsFolder, `${tag}.sql`),
      "utf8"
    );
    const hash = createHash("sha256").update(content).digest("hex");
    await sql`
      INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
      VALUES (${hash}, ${entry.when})`;
  }
}

/**
 * Refuse to run automatic migrations against a populated database
 * that has no journal: it was managed by push and running the full
 * migration history against it would fail or corrupt it.
 */
export async function assertSafeToMigrate(sql: postgres.Sql): Promise<void> {
  if (await journalExists(sql)) return;
  if (!(await databaseIsPopulated(sql))) return;

  throw new Error(
    [
      "This database has tables but no migrations journal, it was likely",
      "managed with `drizzle-kit push`. Running migrations now would replay",
      "the full history against an existing schema.",
      "",
      "Baseline it first (dry run, then --apply):",
      "  npm run db:baseline",
      "  npm run db:baseline -- --apply",
      "",
      "See docs/operations/adopting-an-existing-database.md",
    ].join("\n")
  );
}
