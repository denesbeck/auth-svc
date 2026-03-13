import { getRedis } from "../lib/redis";
import logger from "./logger";

const redis = getRedis();

/**
 * Per-account lockout to prevent brute-force attacks from distributed IPs.
 *
 * After MAX_FAILED_ATTEMPTS within the LOCKOUT_WINDOW, the account is locked
 * for LOCKOUT_DURATION seconds. The lockout uses progressive backoff:
 * each subsequent lockout doubles the duration.
 */
const FAILED_ATTEMPTS_PREFIX = "failed_login:";
const LOCKOUT_PREFIX = "account_locked:";
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW = 15 * 60; // 15 minutes (TTL for failed attempt counter)
const BASE_LOCKOUT_DURATION = 5 * 60; // 5 minutes base lockout
const MAX_LOCKOUT_DURATION = 60 * 60; // 1 hour max lockout

/**
 * Checks whether the account is currently locked out.
 * Returns the number of seconds remaining if locked, or 0 if not locked.
 */
export async function isAccountLocked(email: string): Promise<number> {
  try {
    const ttl = await redis.ttl(LOCKOUT_PREFIX + email.toLowerCase());
    return ttl > 0 ? ttl : 0;
  } catch (error) {
    logger.error("Account lockout check failed:", error instanceof Error ? error.message : error);
    // Fail open — don't block legitimate users due to Redis errors
    return 0;
  }
}

/**
 * Records a failed login attempt. If the threshold is exceeded, locks the account.
 */
export async function recordFailedAttempt(email: string): Promise<void> {
  const key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
  try {
    const attempts = await redis.incr(key);
    if (attempts === 1) {
      // Set TTL on first failure
      await redis.expire(key, LOCKOUT_WINDOW);
    }

    if (attempts >= MAX_FAILED_ATTEMPTS) {
      // Calculate progressive lockout duration based on how many times
      // the account has been locked before (stored as a separate counter)
      const lockCountKey = `lockout_count:${email.toLowerCase()}`;
      const lockCount = await redis.incr(lockCountKey);
      // Expire lockout count after 24 hours of no lockouts
      await redis.expire(lockCountKey, 24 * 60 * 60);

      const duration = Math.min(
        BASE_LOCKOUT_DURATION * Math.pow(2, lockCount - 1),
        MAX_LOCKOUT_DURATION,
      );

      await redis.set(LOCKOUT_PREFIX + email.toLowerCase(), "1", "EX", Math.ceil(duration));
      // Reset failed attempts counter
      await redis.del(key);

      logger.warn(
        `Account locked: ${email} (attempt #${attempts}, lockout ${Math.ceil(duration)}s)`,
      );
    }
  } catch (error) {
    logger.error(
      "Failed to record login attempt:",
      error instanceof Error ? error.message : error,
    );
  }
}

/**
 * Clears failed login attempts after a successful login.
 */
export async function clearFailedAttempts(email: string): Promise<void> {
  try {
    await redis.del(FAILED_ATTEMPTS_PREFIX + email.toLowerCase());
    await redis.del(`lockout_count:${email.toLowerCase()}`);
  } catch (error) {
    logger.error(
      "Failed to clear login attempts:",
      error instanceof Error ? error.message : error,
    );
  }
}
