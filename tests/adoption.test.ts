import { describe, it, expect, afterAll } from "vitest";
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
