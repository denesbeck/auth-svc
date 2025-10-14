import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import postgres from "../lib/postgres";
import redis from "../lib/redis";
import logger from "../utils/logger";
import { validate } from "../lib/time2fa";

const pgClient = postgres().getInstance();
const redisClient = redis().getInstance();

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
