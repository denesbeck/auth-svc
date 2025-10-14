import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import postgres from "../lib/postgres";
import redis from "../lib/redis";
import crypto from "crypto";
import logger from "../utils/logger";
import { validationResult } from "express-validator";
import { validationErrorResponse } from "../utils/validation";

const pgClient = postgres().getInstance();
const redisClient = redis().getInstance();

export const login = async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const combined = validationErrorResponse(errors);
    res.status(400).json({ message: combined });
    return;
  }

  const { email, password } = req.body;
  logger.debug(`Login process started for \`${email}\`...`);

  let salt, password_hash;
  try {
    const { rows } = await pgClient.query(
      `SELECT salt, password_hash FROM users WHERE email = $1 LIMIT 1;`,
      [email],
    );
    if (rows.length === 0) {
      logger.debug(`No records for \`${email}\`.`);
      res.status(401).json({ message: "Invalid credentials." });
      return;
    }
    salt = rows[0].salt;
    password_hash = rows[0].password_hash;
  } catch (error) {
    logger.error(error);
    res.status(503).json({ message: "Unable to login." });
    return;
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(salt + password)
    .digest("hex");

  if (password_hash === hashedPassword) {
    logger.debug(`Password match for \`${email}\`.`);

    const token = jwt.sign({ email }, process.env.JWT_SECRET || "jwt_secret", {
      expiresIn: "4h",
    });

    try {
      await redisClient.set(email, token);
      await redisClient.expire(email, 60 * 60 * 4);
    } catch (error) {
      logger.error(error);
      res.status(503).json({ message: "Unable to communicate with server." });
      return;
    }

    try {
      res.cookie("auth_token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 4 * 60 * 60 * 1000,
      });

      logger.debug(`Token stored in cookie for \`${email}\`.`);
      res.status(200).json({
        success: true,
        redirectUrl: process.env.REDIRECT_URL || "http://localhost:3000",
      });
    } catch (error) {
      logger.error(error);
      res.status(503).json({ message: "Unable to set cookie." });
      return;
    }
  } else {
    logger.debug(`Password mismatch for \`${email}\``);
    res.status(401).json({ message: "Invalid credentials." });
  }
};

export const register = async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const combined = validationErrorResponse(errors);
    res.status(400).json({ message: combined });
    return;
  }

  const { email, password } = req.body;
  logger.debug(`Registration process started for \`${email}\`...`);

  const salt = crypto.randomBytes(32).toString("hex");
  const hashedPassword = crypto
    .createHash("sha256")
    .update(salt + password)
    .digest("hex");

  // TODO: Use KMS to store MFA secret
  try {
    await pgClient.query(
      `INSERT INTO users(email, salt, password_hash, mfa_secret) VALUES($1, $2, $3, $4); `,
      [email, salt, hashedPassword],
    );
  } catch (error) {
    if (error.code === "23505" && error.detail.includes("already exists")) {
      logger.debug(`User \`${email}\` already registered.`);
      res.status(409).json({ message: "User already registered." });
      return;
    }
    logger.error(error);
    res.status(503).json({ message: "Unable to register." });
    return;
  }
  logger.debug(`User \`${email}\` registered.`);
  res.status(200).json({ message: "ok" });
};
