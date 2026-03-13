import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import { getPool } from "../lib/postgres";
import { getRedis } from "../lib/redis";
import logger from "../utils/logger";
import { generateAuthorizationCode } from "../utils/pkce";
import { renderConsentPage, renderErrorPage, renderLoginPage } from "../views/consent";

const pool = getPool();
const redis = getRedis();

// Store pending authorization requests in Redis (keyed by a session token)
const PENDING_AUTH_PREFIX = "pending_auth:";
const PENDING_AUTH_TTL = 600; // 10 minutes

/**
 * GET /authorize
 *
 * Authorization endpoint. Validates the OAuth request parameters,
 * then shows a login page. After login, shows a consent page.
 */
export const authorize = async (req: Request, res: Response) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query as Record<string, string>;

  // Validate response_type
  if (response_type !== "code") {
    res.status(400).send(renderErrorPage("Invalid request", "response_type must be 'code'."));
    return;
  }

  // Validate client_id
  if (!client_id) {
    res.status(400).send(renderErrorPage("Invalid request", "client_id is required."));
    return;
  }

  // Look up the client
  let client: {
    client_id: string;
    client_name: string | null;
    redirect_uris: string[];
    scope: string;
  };
  try {
    const { rows } = await pool.query(
      `SELECT client_id, client_name, redirect_uris, scope FROM oauth_clients WHERE client_id = $1`,
      [client_id],
    );
    if (rows.length === 0) {
      res.status(400).send(renderErrorPage("Invalid client", "Unknown client_id."));
      return;
    }
    client = rows[0];
  } catch (error) {
    logger.error(error);
    res.status(500).send(renderErrorPage("Server error", "Unable to look up client."));
    return;
  }

  // Validate redirect_uri
  const resolvedRedirectUri = redirect_uri || client.redirect_uris[0];
  if (!resolvedRedirectUri || !client.redirect_uris.includes(resolvedRedirectUri)) {
    res
      .status(400)
      .send(renderErrorPage("Invalid request", "redirect_uri does not match any registered URI."));
    return;
  }

  // PKCE is required (OAuth 2.1 / MCP)
  if (!code_challenge) {
    redirectWithError(
      res,
      resolvedRedirectUri,
      "invalid_request",
      "code_challenge is required (PKCE).",
      state,
    );
    return;
  }

  const method = code_challenge_method || "S256";
  if (method !== "S256") {
    redirectWithError(
      res,
      resolvedRedirectUri,
      "invalid_request",
      "Only S256 code_challenge_method is supported.",
      state,
    );
    return;
  }

  // Store the authorization request in Redis so we can retrieve it after login
  const sessionToken = generateAuthorizationCode(); // reuse as session ID
  const pendingAuth = {
    client_id,
    client_name: client.client_name,
    redirect_uri: resolvedRedirectUri,
    scope: scope || client.scope || "",
    state: state || "",
    code_challenge,
    code_challenge_method: method,
  };

  try {
    await redis.set(
      PENDING_AUTH_PREFIX + sessionToken,
      JSON.stringify(pendingAuth),
      "EX",
      PENDING_AUTH_TTL,
    );
  } catch (error) {
    logger.error(error);
    redirectWithError(
      res,
      resolvedRedirectUri,
      "server_error",
      "Unable to process authorization request.",
      state,
    );
    return;
  }

  // Show login page
  res.status(200).send(renderLoginPage(sessionToken));
};

/**
 * POST /authorize/login
 *
 * Handles the login form submission. Authenticates the user,
 * then shows the consent screen.
 */
export const authorizeLogin = async (req: Request, res: Response) => {
  const { email, password, session_token } = req.body;

  if (!email || !password || !session_token) {
    res
      .status(400)
      .send(renderErrorPage("Invalid request", "Email, password, and session are required."));
    return;
  }

  // Retrieve pending auth request
  let pendingAuth: {
    client_id: string;
    client_name: string | null;
    redirect_uri: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
  };
  try {
    const data = await redis.get(PENDING_AUTH_PREFIX + session_token);
    if (!data) {
      res
        .status(400)
        .send(
          renderErrorPage(
            "Session expired",
            "Authorization session has expired. Please start over.",
          ),
        );
      return;
    }
    pendingAuth = JSON.parse(data);
  } catch (error) {
    logger.error(error);
    res.status(500).send(renderErrorPage("Server error", "Unable to retrieve session."));
    return;
  }

  // Authenticate user
  let user: { id: string; email: string };
  try {
    const { rows } = await pool.query(
      `SELECT id, email, password_hash FROM users WHERE email = $1 LIMIT 1`,
      [email],
    );
    if (rows.length === 0) {
      res.status(401).send(renderLoginPage(session_token, "Invalid email or password."));
      return;
    }

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) {
      res.status(401).send(renderLoginPage(session_token, "Invalid email or password."));
      return;
    }
    user = { id: rows[0].id, email: rows[0].email };
  } catch (error) {
    logger.error(error);
    res.status(500).send(renderErrorPage("Server error", "Unable to authenticate."));
    return;
  }

  // Store user_id in the pending auth session
  const updatedAuth = { ...pendingAuth, user_id: user.id };
  try {
    await redis.set(
      PENDING_AUTH_PREFIX + session_token,
      JSON.stringify(updatedAuth),
      "EX",
      PENDING_AUTH_TTL,
    );
  } catch (error) {
    logger.error(error);
    res.status(500).send(renderErrorPage("Server error", "Unable to update session."));
    return;
  }

  // Show consent page
  const scopes = pendingAuth.scope ? pendingAuth.scope.split(" ").filter(Boolean) : [];
  res.status(200).send(
    renderConsentPage({
      sessionToken: session_token,
      clientName: pendingAuth.client_name || pendingAuth.client_id,
      scopes,
      userEmail: user.email,
    }),
  );
};

/**
 * POST /authorize/consent
 *
 * Handles consent approval/denial. If approved, generates an authorization code
 * and redirects back to the client.
 */
export const authorizeConsent = async (req: Request, res: Response) => {
  const { session_token, decision } = req.body;

  if (!session_token) {
    res.status(400).send(renderErrorPage("Invalid request", "Missing session token."));
    return;
  }

  // Retrieve pending auth
  let pendingAuth: {
    client_id: string;
    redirect_uri: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    user_id: string;
  };
  try {
    const data = await redis.get(PENDING_AUTH_PREFIX + session_token);
    if (!data) {
      res
        .status(400)
        .send(
          renderErrorPage(
            "Session expired",
            "Authorization session has expired. Please start over.",
          ),
        );
      return;
    }
    pendingAuth = JSON.parse(data);

    // Clean up the session
    await redis.del(PENDING_AUTH_PREFIX + session_token);
  } catch (error) {
    logger.error(error);
    res.status(500).send(renderErrorPage("Server error", "Unable to retrieve session."));
    return;
  }

  if (!pendingAuth.user_id) {
    res.status(400).send(renderErrorPage("Invalid state", "User not authenticated."));
    return;
  }

  // User denied
  if (decision !== "approve") {
    redirectWithError(
      res,
      pendingAuth.redirect_uri,
      "access_denied",
      "User denied the authorization request.",
      pendingAuth.state,
    );
    return;
  }

  // Generate authorization code
  const code = generateAuthorizationCode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  try {
    await pool.query(
      `INSERT INTO authorization_codes (
        code, client_id, user_id, redirect_uri, scope,
        code_challenge, code_challenge_method, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        code,
        pendingAuth.client_id,
        pendingAuth.user_id,
        pendingAuth.redirect_uri,
        pendingAuth.scope,
        pendingAuth.code_challenge,
        pendingAuth.code_challenge_method,
        expiresAt,
      ],
    );
  } catch (error) {
    logger.error(error);
    redirectWithError(
      res,
      pendingAuth.redirect_uri,
      "server_error",
      "Unable to generate authorization code.",
      pendingAuth.state,
    );
    return;
  }

  logger.info(`Authorization code issued for client ${pendingAuth.client_id}`);

  // Redirect back to client with code
  const issuer = process.env.ISSUER_URL || `http://localhost:${process.env.PORT || 4001}`;
  const redirectUrl = new URL(pendingAuth.redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (pendingAuth.state) {
    redirectUrl.searchParams.set("state", pendingAuth.state);
  }
  redirectUrl.searchParams.set("iss", issuer);

  res.redirect(302, redirectUrl.toString());
};

/**
 * Redirects the user-agent back to the client with an error.
 */
function redirectWithError(
  res: Response,
  redirectUri: string,
  error: string,
  errorDescription: string,
  state?: string,
) {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", errorDescription);
  if (state) {
    url.searchParams.set("state", state);
  }
  res.redirect(302, url.toString());
}
