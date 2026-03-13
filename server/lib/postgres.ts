import { Pool, type PoolConfig } from "pg";
import logger from "../utils/logger";

let pool: Pool | null = null;

function createPool(): Pool {
  const isProduction = process.env.NODE_ENV === "production";
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString && isProduction) {
    throw new Error("DATABASE_URL is required in production. Do not use default dev credentials.");
  }

  const config: PoolConfig = {
    connectionString:
      connectionString || "postgres://postgres:postgres@localhost:5432/csync_auth_dev",
    // Explicit pool limits
    max: isProduction ? 20 : 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
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
