import dotenv from "dotenv";
import express, { Request, Response } from "express";
import logger from "./utils/logger";
import helmet from "helmet";

dotenv.config();

// Import middlewares
import { corsMiddleware } from "./middleware/cors";
import { headersMiddleware } from "./middleware/headers";
import { loggerMiddleware } from "./middleware/logger";
import { authLimiter, oauthLimiter, healthLimiter } from "./middleware/rateLimiters";

// Import OAuth routes
import oauth from "./routes/oauthRoutes";

const app = express();
const port = process.env.PORT || 4001;

app.use(corsMiddleware);
app.use(headersMiddleware);
app.use(loggerMiddleware);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        // Disable upgrade-insecure-requests in development —
        // it causes browsers to rewrite http:// form actions to https://,
        // breaking the OAuth consent flow on localhost.
        ...(process.env.NODE_ENV !== "production"
          ? { "upgrade-insecure-requests": null }
          : {}),
      },
    },
    // Disable HSTS in development — once a browser sees this header,
    // it will force HTTPS for localhost for a year, breaking all HTTP flows.
    strictTransportSecurity: process.env.NODE_ENV === "production",
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check
app.get("/health", healthLimiter, (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// OAuth 2.1 endpoints (mounted at root — MCP expects /authorize, /token, /register, etc.)
app.use("/", oauthLimiter, oauth);

app.listen(port, () => {
  logger.debug(`NODE_ENV=${process.env.NODE_ENV}`);
  logger.info(`Auth service running at http://localhost:${port}`);
});
