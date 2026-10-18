import "dotenv/config";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { defineConfig } from "drizzle-kit";

const databasePath = resolve(process.env.PROJECT_ROOT || process.cwd(), process.env.DB_PATH || "data/bounty.db");
mkdirSync(dirname(databasePath), {recursive:true});

export default defineConfig({
  schema: "./packages/core/src/db/schema.ts",
  out: "./packages/core/src/db/migrations",
  dialect: "sqlite",
  dbCredentials: {
    url: databasePath,
  },
});
