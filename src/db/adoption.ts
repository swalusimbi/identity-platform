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

export async function countJournalRows(sql: postgres.Sql): Promise<number> {
  const rows = await sql`
    SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations`;
  return rows[0].count as number;
}

/**
 * How many leading migrations the live schema reflects, counted from
 * markers without requiring markers for anything newer. Lenient by
 * design: a freshly generated migration with no marker yet must not
 * break the migrate guard.
 */
async function presentMarkerPrefix(sql: postgres.Sql): Promise<number> {
  let count = 0;
  for (const marker of MIGRATION_MARKERS) {
    if (await probeExists(sql, marker.probe)) count += 1;
    else break;
  }
  return count;
}

/**
 * Record the detected migrations as applied, in one transaction. The
 * journal table and all rows commit together or not at all, so an
 * interruption can never leave a partial journal that would fool the
 * migrate guard into replaying history. File reads and hashing happen
 * before the transaction opens, so a bad tag or missing file aborts
 * without any database write.
 */
export async function baselineJournal(
  sql: postgres.Sql,
  appliedTags: string[],
  migrationsFolder = "drizzle"
): Promise<void> {
  const journal = readJournal(migrationsFolder);
  const rows = appliedTags.map((tag) => {
    const entry = journal.find((e) => e.tag === tag);
    if (!entry) throw new Error(`Migration ${tag} is not in the journal`);
    const content = readFileSync(
      path.join(migrationsFolder, `${tag}.sql`),
      "utf8"
    );
    return {
      hash: createHash("sha256").update(content).digest("hex"),
      when: entry.when,
    };
  });

  await sql.begin(async (tx) => {
    await tx`CREATE SCHEMA IF NOT EXISTS drizzle`;
    await tx`
      CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (
        id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint
      )`;

    // Refuse to baseline over an existing journal: it is either already
    // adopted or mid-recovery, and appending would double count
    const [existing] = await tx`
      SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations`;
    if ((existing.count as number) > 0) {
      throw new Error(
        "A migrations journal already exists, refusing to baseline over it. " +
          "To re-baseline, drop it first: DROP SCHEMA drizzle CASCADE"
      );
    }

    for (const row of rows) {
      await tx`
        INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
        VALUES (${row.hash}, ${row.when})`;
    }
  });
}

/**
 * Refuse to run automatic migrations when the database is not in a
 * state migrate can safely advance:
 *   - populated but no journal: push managed, needs baselining
 *   - journal present but recording fewer migrations than the schema
 *     reflects: an interrupted or inconsistent baseline
 */
export async function assertSafeToMigrate(sql: postgres.Sql): Promise<void> {
  const populated = await databaseIsPopulated(sql);
  const hasJournal = await journalExists(sql);

  if (!hasJournal) {
    if (!populated) return; // fresh database, migrate builds it
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

  if (!populated) return;

  // A journal exists on a populated database. It must record at least
  // the migrations the schema visibly reflects, otherwise a baseline
  // was interrupted or the journal was tampered with, and migrate
  // could replay applied migrations.
  const recorded = await countJournalRows(sql);
  const reflected = await presentMarkerPrefix(sql);
  if (recorded < reflected) {
    throw new Error(
      [
        `The migrations journal records ${recorded} migration(s) but the`,
        `schema reflects at least ${reflected}. The journal is incomplete,`,
        "from an interrupted baseline or manual tampering. Recover by",
        "dropping the journal and baselining again:",
        "",
        "  DROP SCHEMA drizzle CASCADE   (in psql)",
        "  npm run db:baseline -- --apply",
        "",
        "See docs/operations/adopting-an-existing-database.md",
      ].join("\n")
    );
  }
}
