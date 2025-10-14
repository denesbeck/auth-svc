import cors from "cors";

const origin =
  process.env.NODE_ENV === "development"
    ? ["http://localhost:3001"]
    : process.env.CORS_ORIGIN;

const corsOptions = {
  origin,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

export const corsMiddleware = cors(corsOptions);
