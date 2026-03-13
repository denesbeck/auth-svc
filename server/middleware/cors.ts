import cors from "cors";

// OAuth authorization server must be accessible from any MCP client origin.
// In production, you may want to restrict this to known client origins.
const origin = process.env.CORS_ORIGIN || true;

const corsOptions = {
  origin,
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

export const corsMiddleware = cors(corsOptions);
