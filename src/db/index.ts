import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

const connectionString = process.env.DATABASE_URL!;

// Connection pool — max 10 for a microservice on your VPS
const sql = postgres(connectionString, { max: 10 });

export const db = drizzle(sql, { schema });
export { sql };
