/**
 * Adopt a database that was managed with `drizzle-kit push`: detect
 * which migrations its schema already reflects and record them in the
 * migrations journal so `npm run db:migrate` applies only what is new.
 *
 * Dry run by default, pass --apply to write the journal.
 *
 *   DATABASE_URL=postgresql://... npx tsx scripts/baseline-migrations.ts
 *   DATABASE_URL=postgresql://... npx tsx scripts/baseline-migrations.ts --apply
 */
import postgres from "postgres";
import {
  detectAppliedMigrations,
  baselineJournal,
  journalExists,
  databaseIsPopulated,
} from "../src/db/adoption";

async function main() {
  const apply = process.argv.includes("--apply");
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  const sql = postgres(process.env.DATABASE_URL, { max: 1 });

  try {
    if (await journalExists(sql)) {
      console.log("A migrations journal already exists, nothing to baseline.");
      return;
    }
    if (!(await databaseIsPopulated(sql))) {
      console.log(
        "This database is empty, run `npm run db:migrate` directly instead."
      );
      return;
    }

    const applied = await detectAppliedMigrations(sql);
    console.log(`Schema reflects ${applied.length} migration(s):`);
    for (const tag of applied) console.log(`  ${tag}`);

    if (!apply) {
      console.log("\nDry run. Rerun with --apply to record these as applied.");
      return;
    }

    await baselineJournal(sql, applied);
    console.log(
      `\n✓ Journal baselined. \`npm run db:migrate\` will now apply only newer migrations.`
    );
  } finally {
    await sql.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
