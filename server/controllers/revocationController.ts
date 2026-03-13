import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import { getPool } from "../lib/postgres";
import logger from "../utils/logger";

const pool = getPool();

/**
 * POST /revoke
 *
 * Token revocation endpoint per RFC 7009.
 * Supports revoking refresh tokens. The server responds with 200 OK
 * regardless of whether the token was found (to prevent token scanning).
 *
 * Required parameters:
 * - token: The token to revoke
 * - client_id: The client that owns the token
 *
 * Optional parameters:
 * - token_type_hint: "refresh_token" (only supported type)
 * - client_secret: Required for confidential clients
 */
export const revokeToken = async (req: Request, res: Response) => {
  // Required headers (consistent with token endpoint)
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");

  const { token, client_id, client_secret, token_type_hint } = req.body;

  if (!token || !client_id) {
    res.status(400).json({
      error: "invalid_request",
      error_description: "token and client_id are required.",
    });
    return;
  }

  // Authenticate client
  try {
    const { rows } = await pool.query(
      `SELECT client_id, client_secret, token_endpoint_auth_method
       FROM oauth_clients WHERE client_id = $1`,
      [client_id],
    );

    if (rows.length === 0) {
      // Per RFC 7009: respond with 200 even if client is unknown (prevent scanning)
      res.sendStatus(200);
      return;
    }

    const client = rows[0];
    if (client.token_endpoint_auth_method === "client_secret_post") {
      if (!client_secret) {
        res.status(401).json({
          error: "invalid_client",
          error_description: "client_secret is required for confidential clients.",
        });
        return;
      }
      if (!client.client_secret) {
        res.status(401).json({
          error: "invalid_client",
          error_description: "Client has no secret configured.",
        });
        return;
      }
      const valid = await bcrypt.compare(client_secret, client.client_secret);
      if (!valid) {
        res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid client_secret.",
        });
        return;
      }
    }
  } catch (error) {
    logger.error("Revocation client auth failed:", error instanceof Error ? error.message : error);
    // Per RFC 7009 Section 2.2: return 503 on server errors
    res.status(503).json({
      error: "server_error",
      error_description: "Unable to process revocation request.",
    });
    return;
  }

  // Revoke the token
  // We only support refresh_token revocation. If token_type_hint is provided
  // and is not "refresh_token", we still attempt to find it as a refresh token
  // (per RFC 7009 Section 2.1: the hint is not binding).
  try {
    const result = await pool.query(
      `UPDATE refresh_tokens SET revoked = true
       WHERE token = $1 AND client_id = $2 AND revoked = false`,
      [token, client_id],
    );

    if (result.rowCount && result.rowCount > 0) {
      logger.info(`Refresh token revoked for client ${client_id}`);
    }
    // Per RFC 7009: always respond with 200, even if token was not found
  } catch (error) {
    logger.error("Token revocation failed:", error instanceof Error ? error.message : error);
    res.status(503).json({
      error: "server_error",
      error_description: "Unable to revoke token.",
    });
    return;
  }

  res.sendStatus(200);
};
