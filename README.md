# auth-svc

OAuth 2.1 Authorization Server for MCP (Model Context Protocol) servers.

Implements the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) with full OAuth 2.1 compliance: authorization code grant with PKCE, dynamic client registration, token refresh with rotation, and Bearer token authentication.

## Architecture

```
┌─────────────┐         ┌──────────────────┐         ┌──────────────┐
│  MCP Client  │──OAuth──▶  auth-svc (this) │◀──JWT───│  MCP Server  │
│  (e.g. IDE)  │         │  Authorization   │         │  (your app)  │
└─────────────┘         │  Server          │         └──────────────┘
                         └────────┬─────────┘
                                  │
                         ┌────────┴─────────┐
                         │  PostgreSQL       │
                         │  Redis            │
                         └──────────────────┘
```

The MCP client authenticates users through this service, receives access tokens, and sends them as `Authorization: Bearer <token>` headers to your MCP server. Your MCP server validates tokens using the exported `bearerAuth` middleware.

## Tech Stack

- **Runtime:** Bun + TypeScript
- **Framework:** Express 5
- **Database:** PostgreSQL (clients, users, authorization codes, refresh tokens)
- **Cache:** Redis (authorization session state)
- **Auth:** bcrypt (passwords), JWT/HS256 (access tokens), PKCE S256
- **Testing:** Vitest

## Quick Start

```bash
cd server

# 1. Install dependencies
bun install

# 2. Configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET to a cryptographically random string

# 3. Start PostgreSQL + Redis
bun run db:up

# 4. Create a user
bun run create-user user@example.com yourpassword

# 5. Start the dev server
bun run dev
```

The server starts at `http://localhost:4001`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST` | `/register` | Dynamic client registration (RFC 7591) |
| `GET` | `/authorize` | Authorization endpoint — shows login page |
| `POST` | `/authorize/login` | Handles login form submission |
| `POST` | `/authorize/consent` | Handles consent approval/denial |
| `POST` | `/token` | Token endpoint — code exchange and refresh |
| `GET` | `/health` | Health check |

## OAuth 2.1 Flow

This is the complete flow an MCP client follows:

### 1. Discovery

```bash
curl http://localhost:4001/.well-known/oauth-authorization-server
```

```json
{
  "issuer": "http://localhost:4001",
  "authorization_endpoint": "http://localhost:4001/authorize",
  "token_endpoint": "http://localhost:4001/token",
  "registration_endpoint": "http://localhost:4001/register",
  "scopes_supported": ["mcp:tools", "mcp:resources", "mcp:prompts"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

### 2. Client Registration (once per client)

```bash
curl -X POST http://localhost:4001/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/oauth/callback"],
    "client_name": "My MCP Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "mcp:tools mcp:resources"
  }'
```

Returns `client_id` (and `client_secret` for confidential clients). Store these — you only register once.

### 3. Authorization (user login + consent)

The client opens this URL in the user's browser:

```
http://localhost:4001/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=http://localhost:3000/oauth/callback&
  scope=mcp:tools&
  state=RANDOM_STATE&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256
```

The user logs in and approves. The browser redirects to the callback URL with an authorization code:

```
http://localhost:3000/oauth/callback?code=AUTH_CODE&state=RANDOM_STATE&iss=http://localhost:4001
```

### 4. Token Exchange

```bash
curl -X POST http://localhost:4001/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&code_verifier=CODE_VERIFIER&client_id=CLIENT_ID"
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2...",
  "scope": "mcp:tools"
}
```

### 5. Using the Token

```bash
curl -X POST http://your-mcp-server/v1/mcp \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### 6. Refreshing

```bash
curl -X POST http://localhost:4001/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID"
```

Returns a new access token and a new refresh token (rotation). The old refresh token is revoked.

## PKCE

PKCE (Proof Key for Code Exchange) with S256 is **required** on all authorization requests. This is mandated by both OAuth 2.1 and the MCP specification.

```bash
# Generate a code_verifier (43+ chars, [A-Za-z0-9-._~])
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)

# Derive the code_challenge
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')
```

Send `code_challenge` in the `/authorize` request, send `code_verifier` in the `/token` request.

## Integrating with Your MCP Server

This service exports a `bearerAuth` middleware for your MCP server to validate access tokens:

```typescript
import { bearerAuth } from "auth-svc/server/middleware/bearerAuth";

// Protect an endpoint — requires a valid access token
app.post("/v1/mcp", bearerAuth(), (req, res) => {
  // req.oauth contains: { sub, iss, aud, scope, client_id, jti }
  console.log("Authenticated user:", req.oauth.sub);
});

// Require specific scopes
app.post("/v1/mcp/tools", bearerAuth("mcp:tools"), (req, res) => {
  // Only accessible with mcp:tools scope
});
```

The middleware:
- Extracts the token from the `Authorization: Bearer <token>` header
- Verifies the JWT signature, issuer, and audience
- Checks required scopes
- Returns `401` with `WWW-Authenticate` header on failure (per RFC 6750)
- Attaches the decoded payload to `req.oauth`

> **Note:** Your MCP server must share the same `JWT_SECRET` environment variable as auth-svc.

## Scopes

| Scope | Description |
|-------|-------------|
| `mcp:tools` | Discover and invoke tools |
| `mcp:resources` | Read resources |
| `mcp:prompts` | Use prompts |

These are not standardized by MCP — define scopes that match your server's capabilities.

## Database Schema

Four tables in PostgreSQL:

- **`users`** — Resource owners (email + bcrypt password hash)
- **`oauth_clients`** — Registered OAuth clients (client_id, redirect_uris, grant_types)
- **`authorization_codes`** — Short-lived, single-use codes with PKCE challenge (10 min TTL)
- **`refresh_tokens`** — Long-lived tokens with rotation and revocation (30 day TTL)

See [`config/db/init.sql`](server/config/db/init.sql) for the full schema.

## Security

- **Passwords** hashed with bcrypt (12 rounds)
- **PKCE S256** required on all authorization requests
- **JWT_SECRET** required from environment (no hardcoded fallback)
- **Authorization codes** are single-use; reuse triggers revocation of all associated tokens
- **Refresh token rotation** with revoked-token-reuse detection (revokes all tokens on suspected theft)
- **Redirect URIs** must be localhost or HTTPS
- **Rate limiting** on login and token endpoints (20 req/min), general limit on all routes (60 req/min)
- **Helmet** for secure HTTP headers
- **`Cache-Control: no-store`** and **`Pragma: no-cache`** on all token responses
- **`WWW-Authenticate`** headers on all 401/403 responses per RFC 6750
- **JWT audience validation** on token verification
- **XSS protection** via HTML escaping on all server-rendered pages

## Scripts

```bash
# Start infrastructure (Postgres, Redis, pgAdmin)
bun run db:up

# Start dev server with hot reload
bun run dev

# Create a user
bun run create-user <email> <password>

# Open the login page in your browser (registers a client + generates PKCE)
./scripts/open-login.sh

# Run the integration test suite (server must be running)
bun test

# Compile TypeScript
bun run compile

# Start production server
bun run start
```

## Testing

27 integration tests covering the full OAuth 2.1 flow:

```bash
# Start the server first
bun run dev

# In another terminal
bun test
```

```
 ✓ Discovery (1 test)
 ✓ Dynamic Client Registration (5 tests)
 ✓ Authorization Endpoint (4 tests)
 ✓ Authorization Flow (5 tests)
 ✓ Token Endpoint — Authorization Code Exchange (6 tests)
 ✓ Token Endpoint — Refresh Token (4 tests)
 ✓ Access Token (1 test)
 ✓ Health Check (1 test)
```

Tests cover: metadata shape, client registration validation, login/consent flow, PKCE verification, code exchange, code reuse detection, refresh token rotation, revoked token reuse detection, scope downscoping, JWT claims, and error responses.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | Yes | — | Signing key for access tokens. Use a random string (32+ bytes). |
| `PORT` | No | `4001` | Server port |
| `NODE_ENV` | No | `development` | `development` or `production` |
| `DEBUG` | No | `false` | Enable debug logging |
| `ISSUER_URL` | No | `http://localhost:PORT` | OAuth issuer identifier. Set to your public URL in production. |
| `DATABASE_URL` | No | `postgres://postgres:postgres@localhost:5432/csync_auth_dev` | PostgreSQL connection string |
| `DATABASE_SSL` | No | `false` | Enable SSL for PostgreSQL |
| `REDIS_URL` | No | `redis://localhost:6379` | Redis connection string |
| `CORS_ORIGIN` | No | `*` (all origins) | Allowed CORS origin(s) |

## Docker Services

| Service | Port | Credentials |
|---------|------|-------------|
| PostgreSQL | 5432 | `postgres` / `postgres` |
| pgAdmin | 5050 | `admin@admin.com` / `admin` |
| Redis | 6379 | — |
| RedisInsight | 8001 | — |

## Project Structure

```
server/
  index.ts                          Entry point
  config/db/init.sql                Database schema
  controllers/
    metadataController.ts           GET /.well-known/oauth-authorization-server
    registrationController.ts       POST /register
    authorizeController.ts          GET /authorize, POST /authorize/login, POST /authorize/consent
    tokenController.ts              POST /token
  lib/
    postgres.ts                     PostgreSQL connection pool
    redis.ts                        Redis client
  middleware/
    bearerAuth.ts                   Bearer token validation (for MCP servers)
    cors.ts                         CORS configuration
    headers.ts                      Security headers
    logger.ts                       Request logging
    rateLimiters.ts                 Rate limiting
  routes/
    oauthRoutes.ts                  Route wiring
  utils/
    jwt.ts                          JWT signing and verification
    logger.ts                       Console logger
    pkce.ts                         PKCE utilities
  views/
    consent.ts                      Server-rendered login/consent HTML pages
  scripts/
    create-user.ts                  CLI to create users
    open-login.sh                   Opens the OAuth login page in your browser
  tests/
    oauth.test.ts                   Integration test suite (27 tests)
```

## Standards Compliance

- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12) — Authorization code grant with PKCE, no implicit grant
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) — Authorization Server Metadata
- [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) — Dynamic Client Registration
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE (S256)
- [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) — Bearer Token Usage
- [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) — MCP-specific requirements

## License

ISC
