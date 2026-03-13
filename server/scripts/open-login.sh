#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${ISSUER_URL:-http://localhost:4001}"
REDIRECT_URI="http://localhost:3000"

# 1. Register a client
echo "Registering client..."
REG_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["'"$REDIRECT_URI"'"],
    "client_name": "Test MCP Client",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "mcp:tools mcp:resources"
  }')

CLIENT_ID=$(echo "$REG_RESPONSE" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CLIENT_ID" ]; then
  echo "Registration failed: $REG_RESPONSE"
  exit 1
fi

echo "Client registered: $CLIENT_ID"

# 2. Generate PKCE
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(uuidgen 2>/dev/null || openssl rand -hex 16)

# 3. Build authorize URL
AUTHORIZE_URL="${BASE_URL}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}'))")&scope=mcp%3Atools%20mcp%3Aresources&state=${STATE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo ""
echo "--- Save these for the token exchange later ---"
echo "client_id:     $CLIENT_ID"
echo "code_verifier: $CODE_VERIFIER"
echo "redirect_uri:  $REDIRECT_URI"
echo ""
echo "Opening browser..."
echo ""

# 4. Open in browser
if [[ "$OSTYPE" == "darwin"* ]]; then
  open "$AUTHORIZE_URL"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  xdg-open "$AUTHORIZE_URL"
else
  echo "Open this URL manually:"
  echo "$AUTHORIZE_URL"
fi
