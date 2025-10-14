import dotenv from "dotenv";
import express, { Request, Response } from "express";
import path from "path";

dotenv.config();

// Import middlewares
import { corsMiddleware } from "./middlewares/cors";
import { logger } from "./middlewares/logger";

const app = express();
const port = process.env.PORT || 4000;

app.use(corsMiddleware); // Enable CORS middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(logger); // Enable logging middleware

// Health check endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

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
