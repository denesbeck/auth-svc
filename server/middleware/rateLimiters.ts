import rateLimit from "express-rate-limit";

const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 5, // Limit each IP to 5 requests per windowMs
  message: "Too many login attempts. Please try again later.",
});

const healthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: "Too many health checks. Please try again later.",
});

export { authLimiter, healthLimiter };
