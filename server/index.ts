import dotenv from "dotenv";
import express, { Request, Response } from "express";
import path from "path";
import logger from "./utils/logger";
import helmet from "helmet";
import cookieParser from "cookie-parser";

dotenv.config();

// Import middlewares
import { corsMiddleware } from "./middleware/cors";
import { headersMiddleware } from "./middleware/headers";
import { jwtAuthMiddleware } from "./middleware/jwtAuth";
import { loggerMiddleware } from "./middleware/logger";
import { authLimiter, healthLimiter } from "./middleware/rateLimiters";

// Import routes
import auth from "./routes/authRoutes";

const app = express();
const port = process.env.PORT || 4001;

app.use("/api", corsMiddleware); // Enable cors middleware (/api routes only)
app.use(headersMiddleware); // Enable headers middleware
app.use(loggerMiddleware); // Enable logging middleware
app.use(helmet()); // Setting secure HTTP response headers
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get("/api/v1/health", healthLimiter, (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Authentication route
app.use("/api/v1/auth", authLimiter, auth);

// Example protected route
app.get(
  "/api/v1/check-auth",
  jwtAuthMiddleware,
  (_req: Request, res: Response) => {
    res.status(200).json({
      message: "Authenticated",
      redirectUrl: process.env.REDIRECT_URL || "http://localhost:3000",
    });
  },
);

// Serve static files when in production
if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.resolve(__dirname, "../client")));

  app.get("*splat", (_req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, "../client/index.html"));
  });
}

app.listen(port, () => {
  logger.debug(`NODE_ENV=${process.env.NODE_ENV}`);
  logger.info(`🚀 Server is running at http://localhost:${port}`);
});
