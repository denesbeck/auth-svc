import express from "express";
import { login, register } from "../controllers/authController";

const router = express.Router();

router.get("/login", login);
router.post("/register", register);

router.get("/logout", (_req, res) => {
  res.json({ message: "Logged out successfully" });
});
router.get("/refresh", (_req, res) => {
  res.json({ message: "Token refreshed successfully" });
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
