import rateLimit from "express-rate-limit";

// Strict limiter for login/token endpoints (brute-force targets)
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: {
    error: "too_many_requests",
    error_description: "Too many requests. Please try again later.",
  },
});

// Generous limiter for discovery/registration (not brute-force targets)
const oauthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: {
    error: "too_many_requests",
    error_description: "Too many requests. Please try again later.",
  },
});

const healthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "too_many_requests", error_description: "Too many requests." },
});

export { authLimiter, healthLimiter, oauthLimiter };
