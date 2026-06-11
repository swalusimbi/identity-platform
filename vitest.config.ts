import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    globalSetup: "tests/global-setup.ts",
    setupFiles: ["tests/setup.ts"],
    // Single shared Postgres + Redis, so run files sequentially
    pool: "forks",
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 30000,
  },
});
