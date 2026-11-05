import { readdir, readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "../claims.js";

export async function testDatabase(): Promise<{ postgres: PGlite; db: PluginDatabaseClient }> {
  const postgres = new PGlite();
  await postgres.exec(`CREATE SCHEMA ${DATABASE_NAMESPACE}`);
  const directory = new URL("../../migrations/", import.meta.url);
  for (const file of (await readdir(directory)).filter(name => name.endsWith(".sql")).sort()) {
    await postgres.exec(await readFile(new URL(file, directory), "utf8"));
  }
  const db: PluginDatabaseClient = {
    namespace: DATABASE_NAMESPACE,
    query: async <T>(sql: string, params?: unknown[]) => (await postgres.query<T>(sql, params)).rows,
    execute: async (sql, params) => ({ rowCount: (await postgres.query(sql, params)).affectedRows ?? 0 }),
  };
  return { postgres, db };
}
