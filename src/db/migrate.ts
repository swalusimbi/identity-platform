import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { assertSafeToMigrate } from "./adoption";

/**
 * Apply pending migrations from drizzle/ and exit. The single migrate
 * path for hosts (`npm run db:migrate`) and the container entrypoint.
 * Refuses populated databases that lack the migrations journal, those
 * must be baselined first (docs/operations/adopting-an-existing-database.md).
 */
async function run() {
  const sql = postgres(process.env.DATABASE_URL!, { max: 1 });
  await assertSafeToMigrate(sql);
  await migrate(drizzle(sql), { migrationsFolder: "drizzle" });
  await sql.end();
  console.log("✓ Migrations applied");
}

run().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
