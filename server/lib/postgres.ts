import { Pool, PoolConfig } from "pg";
import { readFileSync } from "fs";
import { join } from "path";

export default function postgres() {
  let instance: Pool | null = null;

  function createPool() {
    return new Pool({
      connectionString:
        process.env.DATABASE_URL ||
        "postgres://postgres:postgres@localhost:5432/csync_auth_dev",
      ssl: process.env.DATABASE_URL
        ? {
            sslmode: "verify-full",
            ca: readFileSync(join(__dirname, "../_certs/postgres")),
          }
        : undefined,
    } as PoolConfig);
  }
  return {
    getInstance: () => {
      if (!instance) {
        instance = createPool();
      }
      return instance;
    },
  };
}
