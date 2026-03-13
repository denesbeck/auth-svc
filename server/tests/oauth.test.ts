import crypto from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * Integration tests for the OAuth 2.1 authorization server.
 *
 * Prerequisites:
 *   - Server running at BASE_URL (default http://localhost:4001)
 *   - Postgres + Redis running
 *   - A test user exists: admin@admin.io / SuperSecret
 *
 * Run with: bun test
 */

const BASE_URL = process.env.TEST_BASE_URL || "http://localhost:4001";
const TEST_USER = { email: "admin@admin.io", password: "SuperSecret" };
const REDIRECT_URI = "http://localhost:3000";

// ── PKCE helpers ──────────────────────────────────────────────────────────────

function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url"); // 43 chars
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
}

// ── Shared state across the full flow ─────────────────────────────────────────

let clientId: string;
let codeVerifier: string;
let codeChallenge: string;
let authorizationCode: string;
let accessToken: string;
let refreshToken: string;

// ── 1. Discovery ──────────────────────────────────────────────────────────────

describe("Discovery", () => {
  it("GET /.well-known/oauth-authorization-server returns valid metadata", async () => {
    const res = await fetch(`${BASE_URL}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.issuer).toBe(BASE_URL);
    expect(body.authorization_endpoint).toBe(`${BASE_URL}/authorize`);
    expect(body.token_endpoint).toBe(`${BASE_URL}/token`);
    expect(body.registration_endpoint).toBe(`${BASE_URL}/register`);
    expect(body.response_types_supported).toContain("code");
    expect(body.grant_types_supported).toContain("authorization_code");
    expect(body.grant_types_supported).toContain("refresh_token");
    expect(body.code_challenge_methods_supported).toContain("S256");
    expect(body.token_endpoint_auth_methods_supported).toContain("none");
    expect(body.scopes_supported).toEqual(
      expect.arrayContaining(["mcp:tools", "mcp:resources", "mcp:prompts"]),
    );
    // Revocation endpoint (RFC 7009)
    expect(body.revocation_endpoint).toBe(`${BASE_URL}/revoke`);
    expect(body.revocation_endpoint_auth_methods_supported).toContain("none");
    expect(body.revocation_endpoint_auth_methods_supported).toContain("client_secret_post");
  });
});

// ── 2. Dynamic Client Registration ───────────────────────────────────────────

describe("Dynamic Client Registration", () => {
  it("POST /register creates a public client", async () => {
    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [REDIRECT_URI],
        client_name: "Test MCP Client",
        grant_types: ["authorization_code", "refresh_token"],
        scope: "mcp:tools mcp:resources",
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.client_id).toBeDefined();
    expect(typeof body.client_id).toBe("string");
    expect(body.redirect_uris).toEqual([REDIRECT_URI]);
    expect(body.grant_types).toContain("authorization_code");
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.client_id_issued_at).toBeTypeOf("number");
    // Public client — no secret
    expect(body.client_secret).toBeUndefined();

    clientId = body.client_id;
  });

  it("POST /register rejects missing redirect_uris", async () => {
    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Bad Client" }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_client_metadata");
  });

  it("POST /register rejects non-HTTPS non-localhost redirect URI", async () => {
    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://evil.com/callback"],
        client_name: "Evil Client",
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_redirect_uri");
  });

  it("POST /register rejects unsupported grant_type", async () => {
    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [REDIRECT_URI],
        grant_types: ["implicit"],
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_client_metadata");
    expect(body.error_description).toContain("implicit");
  });

  it("POST /register creates a confidential client with client_secret", async () => {
    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [REDIRECT_URI],
        client_name: "Confidential Client",
        token_endpoint_auth_method: "client_secret_post",
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.client_secret).toBeDefined();
    expect(typeof body.client_secret).toBe("string");
    expect(body.client_secret_expires_at).toBe(0);
  });
});

// ── 3. Authorization Endpoint ────────────────────────────────────────────────

describe("Authorization Endpoint", () => {
  beforeAll(() => {
    codeVerifier = generateCodeVerifier();
    codeChallenge = generateCodeChallenge(codeVerifier);
  });

  it("GET /authorize returns login page for valid request", async () => {
    const url = new URL(`${BASE_URL}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", REDIRECT_URI);
    url.searchParams.set("scope", "mcp:tools");
    url.searchParams.set("state", "test-state-123");
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    const res = await fetch(url.toString());
    expect(res.status).toBe(200);

    const html = await res.text();
    expect(html).toContain("Sign in");
    expect(html).toContain("session_token");
    expect(html).toContain("/authorize/login");
  });

  it("GET /authorize rejects missing response_type", async () => {
    const url = new URL(`${BASE_URL}/authorize`);
    url.searchParams.set("client_id", clientId);

    const res = await fetch(url.toString());
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("response_type");
  });

  it("GET /authorize rejects unknown client_id", async () => {
    const url = new URL(`${BASE_URL}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", "nonexistent");
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    const res = await fetch(url.toString());
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("Unknown client_id");
  });

  it("GET /authorize redirects with error when code_challenge is missing", async () => {
    const url = new URL(`${BASE_URL}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", REDIRECT_URI);

    const res = await fetch(url.toString(), { redirect: "manual" });
    expect(res.status).toBe(302);

    const location = new URL(res.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toContain("code_challenge");
  });
});

// ── 4. Full Authorization Flow (login → consent → code) ─────────────────────

describe("Authorization Flow", () => {
  let sessionToken: string;

  it("Step 1: GET /authorize returns login page with session token", async () => {
    codeVerifier = generateCodeVerifier();
    codeChallenge = generateCodeChallenge(codeVerifier);

    const url = new URL(`${BASE_URL}/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", REDIRECT_URI);
    url.searchParams.set("scope", "mcp:tools");
    url.searchParams.set("state", "flow-state");
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    const res = await fetch(url.toString());
    expect(res.status).toBe(200);

    const html = await res.text();
    // Extract session_token from hidden input
    const match = html.match(/name="session_token"\s+value="([^"]+)"/);
    expect(match).not.toBeNull();
    sessionToken = match?.[1];
  });

  it("Step 2: POST /authorize/login with wrong password returns login page with error", async () => {
    const res = await fetch(`${BASE_URL}/authorize/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        email: TEST_USER.email,
        password: "WrongPassword",
        session_token: sessionToken,
      }).toString(),
    });

    expect(res.status).toBe(401);
    const html = await res.text();
    expect(html).toContain("Invalid email or password");
    // Session token should still be present for retry
    expect(html).toContain(sessionToken);
  });

  it("Step 3: POST /authorize/login with correct password returns consent page", async () => {
    const res = await fetch(`${BASE_URL}/authorize/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        email: TEST_USER.email,
        password: TEST_USER.password,
        session_token: sessionToken,
      }).toString(),
    });

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Authorize");
    expect(html).toContain("Test MCP Client");
    expect(html).toContain(TEST_USER.email);
    expect(html).toContain("Approve");
    expect(html).toContain("Deny");
    expect(html).toContain(sessionToken);
  });

  it("Step 4a: POST /authorize/consent with deny redirects with access_denied", async () => {
    // We need a fresh session for the deny test since consent consumes the session
    const freshVerifier = generateCodeVerifier();
    const freshChallenge = generateCodeChallenge(freshVerifier);

    // Start a new authorize flow
    const authorizeUrl = new URL(`${BASE_URL}/authorize`);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", clientId);
    authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authorizeUrl.searchParams.set("scope", "mcp:tools");
    authorizeUrl.searchParams.set("state", "deny-state");
    authorizeUrl.searchParams.set("code_challenge", freshChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const authorizeRes = await fetch(authorizeUrl.toString());
    const authorizeHtml = await authorizeRes.text();
    const tokenMatch = authorizeHtml.match(/name="session_token"\s+value="([^"]+)"/);
    const freshSession = tokenMatch?.[1];

    // Login
    await fetch(`${BASE_URL}/authorize/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        email: TEST_USER.email,
        password: TEST_USER.password,
        session_token: freshSession,
      }).toString(),
    });

    // Deny
    const res = await fetch(`${BASE_URL}/authorize/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        session_token: freshSession,
        decision: "deny",
      }).toString(),
      redirect: "manual",
    });

    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location")!);
    expect(location.origin).toBe(REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("deny-state");
  });

  it("Step 4b: POST /authorize/consent with approve redirects with authorization code", async () => {
    const res = await fetch(`${BASE_URL}/authorize/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        session_token: sessionToken,
        decision: "approve",
      }).toString(),
      redirect: "manual",
    });

    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location")!);
    expect(location.origin).toBe(REDIRECT_URI);

    authorizationCode = location.searchParams.get("code")!;
    expect(authorizationCode).toBeDefined();
    expect(authorizationCode.length).toBeGreaterThan(0);
    expect(location.searchParams.get("state")).toBe("flow-state");
    expect(location.searchParams.get("iss")).toBe(BASE_URL);
  });
});

// ── 5. Token Endpoint ────────────────────────────────────────────────────────

describe("Token Endpoint — Authorization Code Exchange", () => {
  it("POST /token exchanges code + code_verifier for tokens", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: authorizationCode,
        code_verifier: codeVerifier,
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");

    const body = await res.json();
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.refresh_token).toBeDefined();
    expect(body.scope).toBe("mcp:tools");

    accessToken = body.access_token;
    refreshToken = body.refresh_token;
  });

  it("POST /token rejects reused authorization code", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: authorizationCode,
        code_verifier: codeVerifier,
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("already been used");
  });

  it("POST /token rejects wrong code_verifier (PKCE failure)", async () => {
    // We need a fresh auth code for this test
    const badVerifier = generateCodeVerifier();
    const realVerifier = generateCodeVerifier();
    const realChallenge = generateCodeChallenge(realVerifier);

    // Quick flow to get a fresh code
    const code = await getAuthorizationCode(realChallenge, "pkce-state");

    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: badVerifier, // wrong verifier
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("PKCE");
  });

  it("POST /token rejects invalid code", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "totally-fake-code",
        code_verifier: codeVerifier,
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_grant");
  });

  it("POST /token rejects missing params", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
  });

  it("POST /token rejects unsupported grant_type", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "implicit",
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("unsupported_grant_type");
  });
});

// ── 6. Token Endpoint — Refresh Token ────────────────────────────────────────

describe("Token Endpoint — Refresh Token", () => {
  // The code-reuse test above revokes all refresh tokens for this client/user,
  // so we need a fresh set of tokens before testing refresh.
  beforeAll(async () => {
    const freshVerifier = generateCodeVerifier();
    const freshChallenge = generateCodeChallenge(freshVerifier);
    const freshCode = await getAuthorizationCode(freshChallenge, "refresh-setup");

    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: freshCode,
        code_verifier: freshVerifier,
        client_id: clientId,
      }).toString(),
    });

    const body = await res.json();
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
  });

  it("POST /token refreshes tokens with rotation", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe("Bearer");
    expect(body.refresh_token).toBeDefined();
    // New refresh token must be different (rotation)
    expect(body.refresh_token).not.toBe(refreshToken);
    expect(body.scope).toBe("mcp:tools");

    // Update for subsequent tests
    accessToken = body.access_token;
    const oldRefreshToken = refreshToken;
    refreshToken = body.refresh_token;

    // Old refresh token should now be revoked
    const reuseRes = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: oldRefreshToken,
        client_id: clientId,
      }).toString(),
    });

    expect(reuseRes.status).toBe(400);
    const reuseBody = await reuseRes.json();
    expect(reuseBody.error).toBe("invalid_grant");
    expect(reuseBody.error_description).toContain("revoked");
  });

  it("POST /token rejects refresh with wrong client_id", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: "wrong-client-id",
      }).toString(),
    });

    // Unknown client_id is rejected by client authentication before token lookup
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("invalid_client");
  });

  it("POST /token rejects scope escalation on refresh", async () => {
    // Get a fresh token set since the rotation test above revoked the old ones
    const freshVerifier = generateCodeVerifier();
    const freshChallenge = generateCodeChallenge(freshVerifier);
    const freshCode = await getAuthorizationCode(freshChallenge, "scope-test");

    const tokenRes = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: freshCode,
        code_verifier: freshVerifier,
        client_id: clientId,
      }).toString(),
    });
    const tokenBody = await tokenRes.json();

    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokenBody.refresh_token,
        client_id: clientId,
        scope: "mcp:tools mcp:admin", // mcp:admin was never granted
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_scope");
  });

  it("POST /token rejects missing refresh_token", async () => {
    const res = await fetch(`${BASE_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
      }).toString(),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
  });
});

// ── 7. Bearer Token Validation (via JWT decode) ──────────────────────────────

describe("Access Token", () => {
  it("access_token is a valid JWT with correct claims", async () => {
    // Decode without verification (just to check structure)
    const parts = accessToken.split(".");
    expect(parts.length).toBe(3);

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    expect(payload.iss).toBe(BASE_URL);
    expect(payload.aud).toBe(BASE_URL);
    expect(payload.sub).toBeDefined(); // user UUID
    expect(payload.scope).toBe("mcp:tools");
    expect(payload.client_id).toBe(clientId);
    expect(payload.jti).toBeDefined();
    expect(payload.exp).toBeTypeOf("number");
    expect(payload.iat).toBeTypeOf("number");
    // Token should expire in roughly 1 hour
    expect(payload.exp - payload.iat).toBe(3600);
  });
});

// ── 8. Health Check ──────────────────────────────────────────────────────────

describe("Health Check", () => {
  it("GET /health returns status ok", async () => {
    const res = await fetch(`${BASE_URL}/health`);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.status).toBe("ok");
    // uptime and timestamp removed to prevent information disclosure
    expect(body.uptime).toBeUndefined();
    expect(body.timestamp).toBeUndefined();
  });
});

// ── Helper: Run a full auth flow to get an authorization code ────────────────

async function getAuthorizationCode(codeChallenge: string, state: string): Promise<string> {
  // 1. GET /authorize
  const authorizeUrl = new URL(`${BASE_URL}/authorize`);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeUrl.searchParams.set("scope", "mcp:tools");
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  const authorizeRes = await fetch(authorizeUrl.toString());
  const authorizeHtml = await authorizeRes.text();
  const tokenMatch = authorizeHtml.match(/name="session_token"\s+value="([^"]+)"/);
  const sessionToken = tokenMatch?.[1];

  // 2. POST /authorize/login
  await fetch(`${BASE_URL}/authorize/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      email: TEST_USER.email,
      password: TEST_USER.password,
      session_token: sessionToken,
    }).toString(),
  });

  // 3. POST /authorize/consent (approve)
  const consentRes = await fetch(`${BASE_URL}/authorize/consent`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      session_token: sessionToken,
      decision: "approve",
    }).toString(),
    redirect: "manual",
  });

  const location = new URL(consentRes.headers.get("location")!);
  return location.searchParams.get("code")!;
}
