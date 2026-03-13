/**
 * Registers a test client, generates PKCE params, and opens the login page in your browser.
 *
 * Usage: npx ts-node scripts/open-login.ts
 */

import { exec } from "node:child_process";
import crypto from "node:crypto";

const BASE_URL = process.env.ISSUER_URL || "http://localhost:4001";
const REDIRECT_URI = "http://localhost:3000/oauth/callback";

async function main() {
  // 1. Register a client
  console.log("Registering client...");
  const regRes = await fetch(`${BASE_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [REDIRECT_URI],
      client_name: "Test MCP Client",
      grant_types: ["authorization_code", "refresh_token"],
      scope: "mcp:tools mcp:resources",
    }),
  });

  if (!regRes.ok) {
    console.error("Registration failed:", await regRes.text());
    process.exit(1);
  }

  const client = await regRes.json();
  console.log(`Client registered: ${client.client_id}`);

  // 2. Generate PKCE
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier, "ascii")
    .digest("base64url");

  // 3. Build authorize URL
  const url = new URL(`${BASE_URL}/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", client.client_id);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", "mcp:tools mcp:resources");
  url.searchParams.set("state", crypto.randomUUID());
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  console.log("\n--- Save these for the token exchange later ---");
  console.log(`client_id:     ${client.client_id}`);
  console.log(`code_verifier: ${codeVerifier}`);
  console.log(`redirect_uri:  ${REDIRECT_URI}`);
  console.log("\nOpening browser...\n");

  // 4. Open in browser (macOS: open, Linux: xdg-open, Windows: start)
  const openCmd =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";

  exec(`${openCmd} "${url.toString()}"`, (err) => {
    if (err) {
      console.log("Could not open browser automatically. Open this URL manually:");
      console.log(url.toString());
    }
  });
}

main();
