import express from "express";
import { login, mfaConfirm, register } from "../controllers/authController";
import { authValidator } from "../middleware/validators";

const router = express.Router();

router.post("/login", authValidator, login);
router.post("/register", authValidator, register);
router.post("/mfa-confirm", mfaConfirm);

router.get("/logout", (_req, res) => {
  res.json({ message: "Logged out successfully" });
});
router.post("/forgot-password", (_req, res) => {
  res.json({ message: "Password reset link sent" });
});
router.post("/reset-password", (_req, res) => {
  res.json({ message: "Password reset successfully" });
});
router.post("/verify-email", (_req, res) => {
  res.json({ message: "Email verified successfully" });
});
router.post("/resend-verification", (_req, res) => {
  res.json({ message: "Verification email resent successfully" });
});
router.post("/change-password", (_req, res) => {
  res.json({ message: "Password changed successfully" });
});

export default router;
