import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import { getPool } from "../lib/postgres";
import logger from "../utils/logger";
import { generateClientId, generateToken } from "../utils/pkce";

const SALT_ROUNDS = 12;

const pool = getPool();

/**
 * POST /register
 *
 * Dynamic Client Registration per RFC 7591.
 * MCP clients call this to register themselves before starting the OAuth flow.
 */
export const registerClient = async (req: Request, res: Response) => {
  const {
    redirect_uris,
    client_name,
    grant_types,
    response_types,
    token_endpoint_auth_method,
    scope,
  } = req.body;

  // Validate redirect_uris (required)
  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description: "redirect_uris is required and must be a non-empty array.",
    });
    return;
  }

  // Validate each redirect_uri: must be localhost or HTTPS (MCP requirement)
  for (const uri of redirect_uris) {
    try {
      const parsed = new URL(uri);
      const isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      if (!isLocalhost && parsed.protocol !== "https:") {
        res.status(400).json({
          error: "invalid_redirect_uri",
          error_description: `Redirect URI must use HTTPS or localhost: ${uri}`,
        });
        return;
      }
    } catch {
      res.status(400).json({
        error: "invalid_redirect_uri",
        error_description: `Invalid redirect URI: ${uri}`,
      });
      return;
    }
  }

  // Defaults per RFC 7591
  const resolvedGrantTypes = grant_types || ["authorization_code"];
  const resolvedResponseTypes = response_types || ["code"];
  const resolvedAuthMethod = token_endpoint_auth_method || "none";
  const resolvedScope = scope || "";

  // Validate grant_types
  const allowedGrantTypes = ["authorization_code", "refresh_token"];
  for (const gt of resolvedGrantTypes) {
    if (!allowedGrantTypes.includes(gt)) {
      res.status(400).json({
        error: "invalid_client_metadata",
        error_description: `Unsupported grant_type: ${gt}`,
      });
      return;
    }
  }

  // Validate response_types
  if (resolvedResponseTypes.length !== 1 || resolvedResponseTypes[0] !== "code") {
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description: "Only response_type 'code' is supported.",
    });
    return;
  }

  // Validate auth method
  const allowedAuthMethods = ["none", "client_secret_post"];
  if (!allowedAuthMethods.includes(resolvedAuthMethod)) {
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description: `Unsupported token_endpoint_auth_method: ${resolvedAuthMethod}`,
    });
    return;
  }

  // Generate credentials
  const clientId = generateClientId();
  const issuedAt = Math.floor(Date.now() / 1000);

  // Only generate client_secret for confidential clients
  let clientSecret: string | null = null;
  let clientSecretHash: string | null = null;
  const clientSecretExpiresAt = 0;
  if (resolvedAuthMethod !== "none") {
    clientSecret = generateToken();
    // Store hashed secret — plaintext is only returned once in the registration response
    clientSecretHash = await bcrypt.hash(clientSecret, SALT_ROUNDS);
  }

  try {
    await pool.query(
      `INSERT INTO oauth_clients (
        client_id, client_secret, client_name, redirect_uris,
        grant_types, response_types, token_endpoint_auth_method,
        scope, client_id_issued_at, client_secret_expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        clientId,
        clientSecretHash,
        client_name || null,
        redirect_uris,
        resolvedGrantTypes,
        resolvedResponseTypes,
        resolvedAuthMethod,
        resolvedScope,
        issuedAt,
        clientSecretExpiresAt,
      ],
    );
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: "Failed to register client.",
    });
    return;
  }

  logger.info(`Client registered: ${clientId} (${client_name || "unnamed"})`);

  const response: Record<string, unknown> = {
    client_id: clientId,
    client_name: client_name || undefined,
    redirect_uris,
    grant_types: resolvedGrantTypes,
    response_types: resolvedResponseTypes,
    token_endpoint_auth_method: resolvedAuthMethod,
    scope: resolvedScope,
    client_id_issued_at: issuedAt,
  };

  if (clientSecret) {
    response.client_secret = clientSecret;
    response.client_secret_expires_at = clientSecretExpiresAt;
  }

  res.status(201).json(response);
};
