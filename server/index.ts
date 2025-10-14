import dotenv from "dotenv";
import express, { Request, Response } from "express";
import path from "path";

dotenv.config();

// Import middlewares
import { corsMiddleware } from "./middleware/cors";
import { headersMiddleware } from "./middleware/headers";
import { jwtAuthMiddleware } from "./middleware/jwtAuth";
import { loggerMiddleware } from "./middleware/logger";

// Import routes
import auth from "./routes/authRoutes";

const app = express();
const port = process.env.PORT || 4000;

app.use(corsMiddleware); // Enable CORS middleware
app.use(headersMiddleware); // Enable headers middleware
app.use(loggerMiddleware); // Enable logging middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get("/api/v1/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Authentication route
app.use("/api/v1/auth", auth);

// Example protected route
app.get(
  "/api/v1/protected",
  jwtAuthMiddleware,
  (_req: Request, res: Response) => {
    res.json({
      message: "This is a protected route.",
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
  console.log(`🚀 Server is running at http://localhost:${port}`);
});
