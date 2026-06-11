// Loads the test environment before any src module reads process.env
import { config } from "dotenv";
import { resolve } from "path";

config({ path: resolve(__dirname, "../.env.test"), override: true });
