import express from "express";
import { authorizationServerMetadata } from "../controllers/metadataController";
import { registerClient } from "../controllers/registrationController";
import { authorize, authorizeLogin, authorizeConsent } from "../controllers/authorizeController";
import { token } from "../controllers/tokenController";
import { authLimiter } from "../middleware/rateLimiters";

const router = express.Router();

// Discovery
router.get("/.well-known/oauth-authorization-server", authorizationServerMetadata);

// Dynamic Client Registration (RFC 7591)
router.post("/register", registerClient);

// Authorization endpoint
router.get("/authorize", authorize);
router.post("/authorize/login", authLimiter, authorizeLogin);
router.post("/authorize/consent", authorizeConsent);

// Token endpoint (stricter rate limit — brute-force target)
router.post("/token", authLimiter, token);

export default router;
