/**
 * Server-rendered HTML pages for the OAuth authorization flow.
 * Minimal, clean HTML with inline styles — no external dependencies.
 */

function baseLayout(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f0f0f;
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 2rem;
      max-width: 420px;
      width: 100%;
      margin: 1rem;
    }
    h1 { font-size: 1.3rem; margin-bottom: 0.5rem; color: #fff; }
    p { font-size: 0.9rem; color: #999; margin-bottom: 1.2rem; line-height: 1.5; }
    label { display: block; font-size: 0.85rem; color: #bbb; margin-bottom: 0.3rem; }
    input[type="email"], input[type="password"] {
      width: 100%;
      padding: 0.6rem 0.8rem;
      border: 1px solid #333;
      border-radius: 6px;
      background: #111;
      color: #e0e0e0;
      font-size: 0.9rem;
      margin-bottom: 1rem;
      outline: none;
    }
    input:focus { border-color: #4a9eff; }
    .btn {
      display: inline-block;
      padding: 0.6rem 1.2rem;
      border: none;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.15s;
    }
    .btn-primary { background: #4a9eff; color: #fff; width: 100%; }
    .btn-primary:hover { background: #3a8eef; }
    .btn-approve { background: #22c55e; color: #fff; }
    .btn-approve:hover { background: #16a34a; }
    .btn-deny { background: #333; color: #ccc; }
    .btn-deny:hover { background: #444; }
    .btn-group { display: flex; gap: 0.8rem; margin-top: 1rem; }
    .btn-group .btn { flex: 1; text-align: center; }
    .scopes { margin: 1rem 0; }
    .scope-item {
      display: flex;
      align-items: center;
      padding: 0.5rem 0.7rem;
      background: #111;
      border: 1px solid #2a2a2a;
      border-radius: 6px;
      margin-bottom: 0.4rem;
      font-size: 0.85rem;
      color: #ccc;
    }
    .scope-item::before {
      content: "\\2713";
      color: #4a9eff;
      margin-right: 0.6rem;
      font-weight: bold;
    }
    .error-msg {
      background: #2d1515;
      border: 1px solid #5c2020;
      color: #f87171;
      padding: 0.6rem 0.8rem;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }
    .user-badge {
      font-size: 0.85rem;
      color: #4a9eff;
      margin-bottom: 1rem;
    }
  </style>
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;
}

/**
 * Login page shown when the user navigates to /authorize.
 */
export function renderLoginPage(sessionToken: string, error?: string): string {
  const errorHtml = error ? `<div class="error-msg">${escapeHtml(error)}</div>` : "";

  return baseLayout(
    "Sign In",
    `
    <h1>Sign in</h1>
    <p>An application is requesting access to your account.</p>
    ${errorHtml}
    <form method="POST" action="/authorize/login">
      <input type="hidden" name="session_token" value="${escapeHtml(sessionToken)}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
      <button type="submit" class="btn btn-primary">Sign in</button>
    </form>
    `,
  );
}

/**
 * Consent page shown after successful authentication.
 */
export function renderConsentPage(params: {
  sessionToken: string;
  clientName: string;
  scopes: string[];
  userEmail: string;
}): string {
  const scopeDescriptions: Record<string, string> = {
    "mcp:tools": "Discover and invoke tools",
    "mcp:resources": "Read resources",
    "mcp:prompts": "Use prompts",
    "mcp:admin": "Administrative access",
  };

  const scopesHtml = params.scopes.length > 0
    ? `<div class="scopes">
        ${params.scopes.map((s) => `<div class="scope-item">${escapeHtml(scopeDescriptions[s] || s)}</div>`).join("")}
       </div>`
    : `<div class="scopes"><div class="scope-item">Basic access</div></div>`;

  return baseLayout(
    "Authorize",
    `
    <h1>Authorize ${escapeHtml(params.clientName)}</h1>
    <div class="user-badge">Signed in as ${escapeHtml(params.userEmail)}</div>
    <p>This application is requesting the following permissions:</p>
    ${scopesHtml}
    <form method="POST" action="/authorize/consent">
      <input type="hidden" name="session_token" value="${escapeHtml(params.sessionToken)}">
      <div class="btn-group">
        <button type="submit" name="decision" value="deny" class="btn btn-deny">Deny</button>
        <button type="submit" name="decision" value="approve" class="btn btn-approve">Approve</button>
      </div>
    </form>
    `,
  );
}

/**
 * Error page for fatal errors where we can't redirect back to the client.
 */
export function renderErrorPage(title: string, message: string): string {
  return baseLayout(
    "Error",
    `
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    `,
  );
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
