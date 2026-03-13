import crypto from "node:crypto";

/**
 * Validates a code_verifier against a stored code_challenge using S256.
 *
 * S256: BASE64URL(SHA256(ASCII(code_verifier))) === code_challenge
 */
export function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
  method: string = "S256",
): boolean {
  if (method === "S256") {
    const computed = crypto.createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
    return computed === codeChallenge;
  }
  // plain method (only for clients that truly cannot do S256)
  if (method === "plain") {
    return codeVerifier === codeChallenge;
  }
  return false;
}

/**
 * Validates code_verifier format per RFC 7636:
 * - 43-128 characters
 * - Characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
export function isValidCodeVerifier(codeVerifier: string): boolean {
  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false;
  }
  return /^[A-Za-z0-9\-._~]+$/.test(codeVerifier);
}

/**
 * Generates a cryptographically random authorization code.
 */
export function generateAuthorizationCode(): string {
  return crypto.randomBytes(32).toString("base64url");
}

/**
 * Generates a cryptographically random token (for refresh tokens, client secrets, etc.)
 */
export function generateToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}

/**
 * Generates a cryptographically random client ID.
 */
export function generateClientId(): string {
  return crypto.randomBytes(16).toString("base64url");
}
