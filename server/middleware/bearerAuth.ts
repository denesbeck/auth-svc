import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, AccessTokenPayload } from "../utils/jwt";
import logger from "../utils/logger";

// Extend Express Request to carry the authenticated token payload
declare global {
  namespace Express {
    interface Request {
      oauth?: AccessTokenPayload;
    }
  }
}

function getIssuer(): string {
  return process.env.ISSUER_URL || `http://localhost:${process.env.PORT || 4001}`;
}

/**
 * Bearer token authentication middleware for OAuth 2.1.
 *
 * Validates the Authorization: Bearer <token> header.
 * On failure, returns 401 with WWW-Authenticate header per RFC 6750.
 *
 * Optionally accepts required scopes to check.
 */
export function bearerAuth(...requiredScopes: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const issuer = getIssuer();

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).set(
        "WWW-Authenticate",
        `Bearer realm="mcp"`,
      ).json({ error: "unauthorized" });
      return;
    }

    const token = authHeader.slice(7);

    let payload: AccessTokenPayload;
    try {
      payload = verifyAccessToken(token, issuer);
    } catch (error) {
      logger.debug("Invalid bearer token");
      res.status(401).set(
        "WWW-Authenticate",
        `Bearer realm="mcp", error="invalid_token", error_description="The access token is invalid or expired"`,
      ).json({ error: "invalid_token" });
      return;
    }

    // Check required scopes
    if (requiredScopes.length > 0) {
      const tokenScopes = payload.scope ? payload.scope.split(" ") : [];
      const missing = requiredScopes.filter((s) => !tokenScopes.includes(s));
      if (missing.length > 0) {
        res.status(403).set(
          "WWW-Authenticate",
          `Bearer realm="mcp", error="insufficient_scope", scope="${requiredScopes.join(" ")}"`,
        ).json({
          error: "insufficient_scope",
          error_description: `Missing required scope(s): ${missing.join(", ")}`,
        });
        return;
      }
    }

    req.oauth = payload;
    next();
  };
}
