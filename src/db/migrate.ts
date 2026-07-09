import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

/**
 * Apply pending migrations from drizzle/ and exit. Used by the
 * container entrypoint, where drizzle-kit (a dev dependency) is not
 * installed. `npm run db:migrate` remains the host-side equivalent.
 */
async function run() {
  const sql = postgres(process.env.DATABASE_URL!, { max: 1 });
  await migrate(drizzle(sql), { migrationsFolder: "drizzle" });
  await sql.end();
  console.log("✓ Migrations applied");
}

run().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
