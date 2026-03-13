import express from "express";
import { authorize, authorizeConsent, authorizeLogin } from "../controllers/authorizeController";
import { authorizationServerMetadata } from "../controllers/metadataController";
import { registerClient } from "../controllers/registrationController";
import { revokeToken } from "../controllers/revocationController";
import { token } from "../controllers/tokenController";
import { loginLimiter, registrationLimiter, tokenLimiter } from "../middleware/rateLimiters";

const router = express.Router();

// Discovery
router.get("/.well-known/oauth-authorization-server", authorizationServerMetadata);

// Dynamic Client Registration (RFC 7591) — stricter rate limit to prevent abuse
router.post("/register", registrationLimiter, registerClient);

// Authorization endpoint
router.get("/authorize", authorize);
router.post("/authorize/login", loginLimiter, authorizeLogin);
router.post("/authorize/consent", authorizeConsent);

// Token endpoint — separate limiter (authenticated by code/secret, not passwords)
router.post("/token", tokenLimiter, token);

// Token revocation endpoint (RFC 7009)
router.post("/revoke", tokenLimiter, revokeToken);

export default router;
