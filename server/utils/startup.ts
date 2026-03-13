import logger from "./logger";

/**
 * Validates environment configuration at startup.
 * Throws in production if critical variables are missing or insecure.
 * Warns in development for non-critical issues.
 */
export function validateEnvironment(): void {
  const isProduction = process.env.NODE_ENV === "production";

  // JWT_SECRET is validated by getJwtSecret() on first use,
  // but we validate early to fail fast at startup.
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error("JWT_SECRET is required. Set it to a random string of at least 32 characters.");
  }
  if (jwtSecret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters.");
  }
  const placeholders = ["change-me", "changeme", "your-secret", "replace-me", "example"];
  for (const p of placeholders) {
    if (jwtSecret.toLowerCase().includes(p)) {
      throw new Error(
        `JWT_SECRET contains placeholder '${p}'. Generate a real secret: openssl rand -base64 48`,
      );
    }
  }

  if (isProduction) {
    // DATABASE_URL must be explicitly set — no fallback to dev credentials
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is required in production.");
    }

    // REDIS_URL must be explicitly set
    if (!process.env.REDIS_URL) {
      throw new Error("REDIS_URL is required in production.");
    }

    // CORS_ORIGIN must be set — no open CORS in production
    if (!process.env.CORS_ORIGIN) {
      throw new Error(
        "CORS_ORIGIN is required in production. Set it to the allowed origin(s), comma-separated.",
      );
    }

    // ISSUER_URL must be HTTPS in production
    const issuer = process.env.ISSUER_URL;
    if (!issuer) {
      throw new Error("ISSUER_URL is required in production.");
    }
    if (!issuer.startsWith("https://")) {
      throw new Error("ISSUER_URL must use HTTPS in production.");
    }

    // DATABASE_SSL should be enabled
    if (process.env.DATABASE_SSL !== "true") {
      logger.warn("DATABASE_SSL is not enabled. Database connections are unencrypted.");
    }

    // Debug should be off
    if (process.env.DEBUG === "true") {
      logger.warn("DEBUG is enabled in production. This may expose sensitive information in logs.");
    }
  } else {
    // Development warnings
    if (!process.env.DATABASE_URL) {
      logger.warn("DATABASE_URL not set — using development default (localhost).");
    }
    if (!process.env.REDIS_URL) {
      logger.warn("REDIS_URL not set — using development default (localhost).");
    }
  }
}
