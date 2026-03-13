import type { Request, Response } from "express";

function getIssuer(): string {
  return process.env.ISSUER_URL || `http://localhost:${process.env.PORT || 4001}`;
}

/**
 * GET /.well-known/oauth-authorization-server
 *
 * Returns OAuth 2.0 Authorization Server Metadata per RFC 8414.
 * MCP clients use this to discover endpoints.
 */
export const authorizationServerMetadata = (_req: Request, res: Response) => {
  const issuer = getIssuer();

  res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    scopes_supported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
  });
};
