import { describe, it, expect, afterAll, beforeEach } from "vitest";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { sql } from "../src/db";
import {
  MIGRATION_MARKERS,
  readJournal,
  journalExists,
  databaseIsPopulated,
  detectAppliedMigrations,
  baselineJournal,
  assertSafeToMigrate,
  countJournalRows,
  assertJournalMatchesSchemaPrefix,
} from "../src/db/adoption";

/**
 * The test database is itself the adoption scenario: populated by
 * `drizzle-kit push` in global setup, with no migrations journal.
 */

afterAll(async () => {
  // Leave the database journal-less again for other runs
  await sql`DROP SCHEMA IF EXISTS drizzle CASCADE`;
});

describe("database adoption", () => {
  it("has a marker for every migration in the journal", () => {
    const markerTags = MIGRATION_MARKERS.map((m) => m.tag);
    const journalTags = readJournal().map((e) => e.tag);
    expect(markerTags).toEqual(journalTags);
  });

  it("recognizes a push managed database and refuses to migrate it", async () => {
    expect(await journalExists(sql)).toBe(false);
    expect(await databaseIsPopulated(sql)).toBe(true);

    await expect(assertSafeToMigrate(sql)).rejects.toThrow(/baseline/i);
  });

  it("detects the full applied prefix from the live schema", async () => {
    const applied = await detectAppliedMigrations(sql);
    expect(applied).toEqual(readJournal().map((e) => e.tag));
  });

  it("baselines the journal and unlocks a no-op migrate", async () => {
    const applied = await detectAppliedMigrations(sql);
    await baselineJournal(sql, applied);

    expect(await journalExists(sql)).toBe(true);
    const rows = await sql`
      SELECT hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id`;
    expect(rows.length).toBe(applied.length);
    // Timestamps come from the journal, hashes from the real files
    expect(Number(rows[rows.length - 1].created_at)).toBe(
      readJournal().at(-1)!.when
    );
    expect(rows[0].hash).toMatch(/^[0-9a-f]{64}$/);

    // The guard now passes and migrating applies nothing new
    await assertSafeToMigrate(sql);
    await migrate(drizzle(sql), { migrationsFolder: "drizzle" });
    const after = await sql`
      SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations`;
    expect(after[0].count).toBe(applied.length);
  });
});

describe("adoption safety (FUP-02)", () => {
  // Each test starts journal-less; the outer afterAll drops the schema
  beforeEach(async () => {
    await sql`DROP SCHEMA IF EXISTS drizzle CASCADE`;
  });

  it("refuses to re-baseline over an existing journal and adds nothing", async () => {
    const applied = await detectAppliedMigrations(sql);
    await baselineJournal(sql, applied);
    const before = await countJournalRows(sql);

    await expect(baselineJournal(sql, applied)).rejects.toThrow(/already exists/i);
    expect(await countJournalRows(sql)).toBe(before);
  });

  it("leaves no journal when a bad tag aborts the baseline", async () => {
    await expect(
      baselineJournal(sql, ["0000_known_maria_hill", "9999_does_not_exist"])
    ).rejects.toThrow(/not in the journal/i);

    // The pre-write validation ran before any transaction, so nothing
    // was created, no schema, no partial journal
    expect(await journalExists(sql)).toBe(false);
  });

  it("rolls back earlier inserts when a later journal insert fails", async () => {
    await sql`CREATE SCHEMA drizzle`;
    await sql`
      CREATE TABLE drizzle.__drizzle_migrations (
        id SERIAL PRIMARY KEY CHECK (id < 2),
        hash text NOT NULL,
        created_at bigint
      )`;

    const applied = await detectAppliedMigrations(sql);
    await expect(baselineJournal(sql, applied)).rejects.toThrow();

    expect(await countJournalRows(sql)).toBe(0);
  });

  it("rejects an interrupted baseline: journal behind the schema", async () => {
    // Simulate a partial journal a pre-fix interrupted baseline could
    // have left: the table exists but records fewer migrations than
    // the schema reflects
    await sql`CREATE SCHEMA IF NOT EXISTS drizzle`;
    await sql`
      CREATE TABLE drizzle.__drizzle_migrations (
        id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint
      )`;
    await sql`
      INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
      VALUES ('deadbeef', ${readJournal()[0].when})`;

    await expect(assertSafeToMigrate(sql)).rejects.toThrow(/incomplete/i);
  });

  it("rejects a full length journal whose recorded prefix is not authentic", async () => {
    await sql`CREATE SCHEMA drizzle`;
    await sql`
      CREATE TABLE drizzle.__drizzle_migrations (
        id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint
      )`;
    const journal = readJournal();
    for (const entry of journal) {
      await sql`
        INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
        VALUES ('deadbeef', ${entry.when})`;
    }

    await expect(assertJournalMatchesSchemaPrefix(sql)).rejects.toThrow(
      /does not match the expected schema prefix/i
    );
  });

  it("passes once the journal records the full reflected prefix", async () => {
    await baselineJournal(sql, await detectAppliedMigrations(sql));
    await expect(assertSafeToMigrate(sql)).resolves.toBeUndefined();
  });
});
