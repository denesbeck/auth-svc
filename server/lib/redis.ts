import Redis from "ioredis";
import logger from "../utils/logger";

let client: Redis | null = null;

export function getRedis(): Redis {
  if (!client) {
    client = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
    client.on("error", (err) => logger.error("Redis error:", err.message));
  }
  return client;
}
