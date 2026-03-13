import type { Request, Response } from "express";
import { getPool } from "../lib/postgres";
import { signAccessToken } from "../utils/jwt";
import logger from "../utils/logger";
import { generateToken, isValidCodeVerifier, verifyCodeChallenge } from "../utils/pkce";

const pool = getPool();

function getIssuer(): string {
  return process.env.ISSUER_URL || `http://localhost:${process.env.PORT || 4001}`;
}

/**
 * POST /token
 *
 * Token endpoint. Supports:
 * - grant_type=authorization_code (with PKCE)
 * - grant_type=refresh_token
 */
export const token = async (req: Request, res: Response) => {
  // Token endpoint uses application/x-www-form-urlencoded
  const grantType = req.body.grant_type;

  // Required headers on all token responses (RFC 6749 Section 5.1)
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");

  if (grantType === "authorization_code") {
    return handleAuthorizationCode(req, res);
  }

  if (grantType === "refresh_token") {
    return handleRefreshToken(req, res);
  }

  res.status(400).json({
    error: "unsupported_grant_type",
    error_description: `Grant type '${grantType}' is not supported.`,
  });
};

/**
 * Authorization code exchange with PKCE validation.
 */
async function handleAuthorizationCode(req: Request, res: Response) {
  const { code, code_verifier, client_id, redirect_uri } = req.body;

  if (!code || !code_verifier || !client_id) {
    res.status(400).json({
      error: "invalid_request",
      error_description: "code, code_verifier, and client_id are required.",
    });
    return;
  }

  // Validate code_verifier format
  if (!isValidCodeVerifier(code_verifier)) {
    res.status(400).json({
      error: "invalid_request",
      error_description: "code_verifier must be 43-128 characters from [A-Za-z0-9-._~].",
    });
    return;
  }

  // Look up the authorization code
  let authCode: {
    code: string;
    client_id: string;
    user_id: string;
    redirect_uri: string;
    scope: string;
    code_challenge: string;
    code_challenge_method: string;
    expires_at: Date;
    used: boolean;
  };
  try {
    const { rows } = await pool.query(
      `SELECT code, client_id, user_id, redirect_uri, scope,
              code_challenge, code_challenge_method, expires_at, used
       FROM authorization_codes WHERE code = $1`,
      [code],
    );

    if (rows.length === 0) {
      res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code is invalid.",
      });
      return;
    }
    authCode = rows[0];
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: "Unable to validate authorization code.",
    });
    return;
  }

  // Check if code was already used (replay attack)
  if (authCode.used) {
    // Per OAuth 2.1: if code is reused, revoke all tokens issued with it
    logger.warn(`Authorization code reuse detected for client ${authCode.client_id}`);
    try {
      await pool.query(
        `UPDATE refresh_tokens SET revoked = true WHERE client_id = $1 AND user_id = $2`,
        [authCode.client_id, authCode.user_id],
      );
    } catch (error) {
      logger.error(error);
    }
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has already been used.",
    });
    return;
  }

  // Check expiration
  if (new Date() > new Date(authCode.expires_at)) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has expired.",
    });
    return;
  }

  // Check client_id matches
  if (authCode.client_id !== client_id) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code was not issued to this client.",
    });
    return;
  }

  // Check redirect_uri matches (if provided)
  if (redirect_uri && redirect_uri !== authCode.redirect_uri) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "redirect_uri does not match the original authorization request.",
    });
    return;
  }

  // Verify PKCE
  if (
    !verifyCodeChallenge(code_verifier, authCode.code_challenge, authCode.code_challenge_method)
  ) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "PKCE code_verifier verification failed.",
    });
    return;
  }

  // Mark the code as used
  try {
    await pool.query(`UPDATE authorization_codes SET used = true WHERE code = $1`, [code]);
  } catch (error) {
    logger.error(error);
  }

  // Issue tokens
  const issuer = getIssuer();
  const accessToken = signAccessToken({
    sub: authCode.user_id,
    iss: issuer,
    aud: issuer,
    scope: authCode.scope,
    client_id: authCode.client_id,
  });

  const refreshToken = generateToken();
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

  try {
    await pool.query(
      `INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [refreshToken, authCode.client_id, authCode.user_id, authCode.scope, refreshExpiresAt],
    );
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: "Unable to issue refresh token.",
    });
    return;
  }

  logger.info(`Tokens issued for client ${authCode.client_id}, user ${authCode.user_id}`);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: authCode.scope,
  });
}

/**
 * Refresh token exchange with rotation.
 */
async function handleRefreshToken(req: Request, res: Response) {
  const { refresh_token, client_id, scope } = req.body;

  if (!refresh_token || !client_id) {
    res.status(400).json({
      error: "invalid_request",
      error_description: "refresh_token and client_id are required.",
    });
    return;
  }

  // Look up the refresh token
  let tokenRecord: {
    token: string;
    client_id: string;
    user_id: string;
    scope: string;
    expires_at: Date;
    revoked: boolean;
  };
  try {
    const { rows } = await pool.query(
      `SELECT token, client_id, user_id, scope, expires_at, revoked
       FROM refresh_tokens WHERE token = $1`,
      [refresh_token],
    );

    if (rows.length === 0) {
      res.status(400).json({
        error: "invalid_grant",
        error_description: "Refresh token is invalid.",
      });
      return;
    }
    tokenRecord = rows[0];
  } catch (error) {
    logger.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: "Unable to validate refresh token.",
    });
    return;
  }

  // Validate
  if (tokenRecord.revoked) {
    // Potential token theft — revoke all tokens for this client/user
    logger.warn(`Revoked refresh token reuse for client ${tokenRecord.client_id}`);
    try {
      await pool.query(
        `UPDATE refresh_tokens SET revoked = true WHERE client_id = $1 AND user_id = $2`,
        [tokenRecord.client_id, tokenRecord.user_id],
      );
    } catch (error) {
      logger.error(error);
    }
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Refresh token has been revoked.",
    });
    return;
  }

  if (new Date() > new Date(tokenRecord.expires_at)) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Refresh token has expired.",
    });
    return;
  }

  if (tokenRecord.client_id !== client_id) {
    res.status(400).json({
      error: "invalid_grant",
      error_description: "Refresh token was not issued to this client.",
    });
    return;
  }

  // Scope downscoping: requested scope must not exceed original
  const originalScopes = (tokenRecord.scope || "").split(" ").filter(Boolean);
  let resolvedScope = tokenRecord.scope || "";
  if (scope) {
    const requestedScopes = scope.split(" ");
    for (const s of requestedScopes) {
      if (!originalScopes.includes(s)) {
        res.status(400).json({
          error: "invalid_scope",
          error_description: `Requested scope '${s}' exceeds the original grant.`,
        });
        return;
      }
    }
    resolvedScope = scope;
  }

  // Rotate: revoke old, issue new (in a transaction for atomicity)
  const newRefreshToken = generateToken();
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

  const pgClient = await pool.connect();
  try {
    await pgClient.query("BEGIN");
    await pgClient.query(`UPDATE refresh_tokens SET revoked = true WHERE token = $1`, [
      refresh_token,
    ]);
    await pgClient.query(
      `INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        newRefreshToken,
        tokenRecord.client_id,
        tokenRecord.user_id,
        resolvedScope,
        refreshExpiresAt,
      ],
    );
    await pgClient.query("COMMIT");
  } catch (error) {
    await pgClient.query("ROLLBACK");
    logger.error(error);
    res.status(500).json({
      error: "server_error",
      error_description: "Unable to rotate refresh token.",
    });
    return;
  } finally {
    pgClient.release();
  }

  // Issue new access token
  const issuer = getIssuer();
  const accessToken = signAccessToken({
    sub: tokenRecord.user_id,
    iss: issuer,
    aud: issuer,
    scope: resolvedScope,
    client_id: tokenRecord.client_id,
  });

  logger.info(`Tokens refreshed for client ${tokenRecord.client_id}, user ${tokenRecord.user_id}`);

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: newRefreshToken,
    scope: resolvedScope,
  });
}
