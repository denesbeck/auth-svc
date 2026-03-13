import { Pool, PoolConfig } from "pg";
import logger from "../utils/logger";

let pool: Pool | null = null;

function createPool(): Pool {
  const config: PoolConfig = {
    connectionString:
      process.env.DATABASE_URL ||
      "postgres://postgres:postgres@localhost:5432/csync_auth_dev",
  };

  // Only enable SSL if DATABASE_URL contains sslmode or SSL env is set
  if (process.env.DATABASE_SSL === "true") {
    config.ssl = { rejectUnauthorized: true };
  }

  const p = new Pool(config);
  p.on("error", (err) => logger.error("PostgreSQL pool error:", err.message));
  return p;
}

export function getPool(): Pool {
  if (!pool) {
    pool = createPool();
  }
  return pool;
}
