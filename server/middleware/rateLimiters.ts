import rateLimit from "express-rate-limit";

// Strict limiter for login endpoint (primary brute-force target)
// 10 login attempts per minute per IP
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "too_many_requests",
    error_description: "Too many login attempts. Please try again later.",
  },
});

// Token endpoint limiter — allows more throughput since token requests
// are authenticated by code/secret, not passwords
const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "too_many_requests",
    error_description: "Too many token requests. Please try again later.",
  },
});

// Strict limiter for client registration (abuse prevention)
const registrationLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "too_many_requests",
    error_description: "Too many registration requests. Please try again later.",
  },
});

// Generous limiter for discovery endpoints (not brute-force targets)
const oauthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "too_many_requests",
    error_description: "Too many requests. Please try again later.",
  },
});

const healthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests", error_description: "Too many requests." },
});

export { healthLimiter, loginLimiter, oauthLimiter, registrationLimiter, tokenLimiter };
