import crypto from "crypto";
import jwt from "jsonwebtoken";

/**
 * JWT signing configuration.
 *
 * For production, use RS256 with a proper key pair.
 * For now, we use HS256 with a secret from environment.
 * The JWKS endpoint will need updating when switching to RS256.
 */

function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      "JWT_SECRET environment variable is required. Set it to a cryptographically random string (min 32 bytes).",
    );
  }
  return secret;
}

export interface AccessTokenPayload {
  sub: string; // user ID
  iss: string; // issuer
  aud: string; // audience (resource server)
  scope: string; // space-delimited scopes
  client_id: string; // OAuth client ID
  jti: string; // unique token ID
  exp?: number;
  iat?: number;
}

/**
 * Signs an access token JWT.
 */
export function signAccessToken(payload: {
  sub: string;
  iss: string;
  aud: string;
  scope: string;
  client_id: string;
  expiresIn?: number; // seconds, default 3600
}): string {
  const jti = crypto.randomUUID();
  const expiresIn = payload.expiresIn || 3600;

  return jwt.sign(
    {
      sub: payload.sub,
      iss: payload.iss,
      aud: payload.aud,
      scope: payload.scope,
      client_id: payload.client_id,
      jti,
    },
    getJwtSecret(),
    {
      algorithm: "HS256",
      expiresIn,
    },
  );
}

/**
 * Verifies and decodes an access token.
 */
export function verifyAccessToken(
  token: string,
  issuer: string,
): AccessTokenPayload {
  return jwt.verify(token, getJwtSecret(), {
    issuer,
    audience: issuer,
    algorithms: ["HS256"],
  }) as AccessTokenPayload;
}
