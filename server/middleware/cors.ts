import cors from "cors";

const origin =
  process.env.NODE_ENV === "development"
    ? "http://localhost:3000"
    : process.env.CORS_ORIGIN;

const corsOptions = {
  origin,
  credentials: true,
};

export const corsMiddleware = cors(corsOptions);
