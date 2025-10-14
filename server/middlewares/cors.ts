import cors from "cors";

const corsOptions = {
  origin: process.env.CORS_ORIGIN || "*", // Allow all by default
};

export const corsMiddleware = cors(corsOptions);
