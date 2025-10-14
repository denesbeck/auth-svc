import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import postgres from "../lib/postgres";
import redis from "../lib/redis";
import crypto from "crypto";
import logger from "../utils/logger";
import { generate, validate } from "../lib/time2fa";
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
    try {
      await redisClient.set(email, "pending_mfa_confirm");
      await redisClient.expire(email, 60 * 5);
      logger.debug(`Pending MFA confirm status set in Redis for \`${email}\``);
    } catch (error) {
      logger.error(error);
      res.status(503).json({ message: "Unable to login." });
      return;
    }
    res.status(200).json({ message: "Pending MFA confirm." });
  } else {
    logger.debug(`Password mismatch for \`${email}\``);
    res.status(401).json({ message: "Invalid credentials." });
  }
};

export const mfaConfirm = async (req: Request, res: Response) => {
  const { email, passcode } = req.body;
  logger.debug(`MFA confirm process started for \`${email}\`...`);

  // TODO: Get MFA secret from KMS
  let mfaEnabled;
  let mfaSecret;
  try {
    const { rows } = await pgClient.query(
      `SELECT mfa_enabled, mfa_secret FROM users WHERE email = $1 LIMIT 1;`,
      [email],
    );
    mfaEnabled = rows[0].mfa_enabled;
    mfaSecret = rows[0].mfa_secret;
  } catch (error) {
    logger.error(error);
    res.status(503).json({ message: "Unable to complete MFA." });
    return;
  }

  logger.debug(
    `MFA is ${mfaEnabled ? "enabled" : "disabled"} for \`${email}\`.`,
  );

  if (mfaEnabled) {
    let status;
    try {
      status = await redisClient.get(email);
      if (status !== "pending_mfa_confirm") {
        logger.debug(
          `Status is not \`${"pending_mfa_confirm"}\` for \`${email}\`.`,
        );
        res.status(401).json({ message: "Unauthorized." });
        return;
      }
    } catch (error) {
      logger.error(error);
      res.status(503).json({ message: "Unable to complete MFA." });
      return;
    }
  }

  const isValid = validate(mfaSecret, passcode);
  logger.debug(
    `MFA validation ${isValid ? "succeeded" : "failed"} for \`${email}\`.`,
  );
  if (!isValid) {
    res.status(401).json({ message: "Unauthorized." });
    return;
  }

  if (!mfaEnabled) {
    try {
      await pgClient.query(
        `UPDATE users SET mfa_enabled = true WHERE email = $1; `,
        [email],
      );
      logger.debug(`MFA setup completed for \`${email}\`.`);
      res.status(200).json({ message: "ok" });
      return;
    } catch (error) {
      logger.error(error);
      res.status(503).json({ message: "Unable to complete MFA setup." });
      return;
    }
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET || "jwt_secret", {
    expiresIn: "4h",
  });

  try {
    await redisClient.set(email, token);
    await redisClient.expire(email, 60 * 60 * 4);
  } catch (error) {
    logger.error(error);
    res.status(503).json({ message: "Unable to complete MFA." });
    return;
  }

  logger.debug(`Token created for \`${email}\`.`);
  res.set("Authorization", `Bearer ${token}`);
  res.redirect(process.env.REDIRECT_URL || "https://google.com");
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
  const { secret, url } = generate(email);

  // TODO: Use KMS to store MFA secret
  try {
    await pgClient.query(
      `INSERT INTO users(email, salt, password_hash, mfa_secret) VALUES($1, $2, $3, $4); `,
      [email, salt, hashedPassword, secret],
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
  res.status(200).json({ message: "ok", url });
};
