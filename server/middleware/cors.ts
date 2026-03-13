import cors from "cors";
import logger from "../utils/logger";

/**
 * CORS configuration.
 *
 * In production, CORS_ORIGIN must be explicitly set to the allowed origin(s).
 * Multiple origins can be comma-separated: "https://app.example.com,https://admin.example.com"
 * In development, if CORS_ORIGIN is not set, localhost origins are allowed.
 */
function resolveOrigin(): cors.CorsOptions["origin"] {
  const envOrigin = process.env.CORS_ORIGIN;

  if (envOrigin) {
    // Support comma-separated multiple origins
    const origins = envOrigin.split(",").map((o) => o.trim()).filter(Boolean);
    if (origins.length === 1) return origins[0];
    return origins;
  }

  // In production, reject requests if CORS_ORIGIN is not configured
  if (process.env.NODE_ENV === "production") {
    logger.warn(
      "CORS_ORIGIN is not set in production. All cross-origin requests will be rejected.",
    );
    return false;
  }

  // In development, allow localhost origins only
  return (origin, callback) => {
    if (!origin) {
      // Allow non-browser requests (curl, Postman, server-to-server)
      callback(null, true);
      return;
    }
    try {
      const parsed = new URL(origin);
      const isLocalhost =
        parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      if (isLocalhost) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: Origin '${origin}' is not allowed in development mode.`));
      }
    } catch {
      callback(new Error("CORS: Invalid origin."));
    }
  };
}

const corsOptions: cors.CorsOptions = {
  origin: resolveOrigin(),
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

export const corsMiddleware = cors(corsOptions);
