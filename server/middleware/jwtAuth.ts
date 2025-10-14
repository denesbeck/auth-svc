import jwt, { JwtPayload } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import redis from "../lib/redis";
import logger from "../utils/logger";

const redisClient = redis().getInstance();

export const jwtAuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = req.cookies.auth_token;

  if (!token) {
    logger.debug("Missing authorization token.");
    res.status(401).json({ message: "Access denied. No token provided." });
    return;
  }

  let email;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    email = (decoded as JwtPayload)?.email;
  } catch (error) {
    logger.error("Invalid token.");
    res.status(401).json({ message: "Access denied. Invalid token." });
    return;
  }

  if (!email) {
    logger.error("Email missing.");
    res.status(401).json({ message: "Access denied. Invalid token." });
    return;
  }

  try {
    const redisToken = await redisClient.get(email);
    if (redisToken !== token) {
      logger.error(`Token mismatch for \`${email}\`.`);
      res.status(401).json({ message: "Access denied. Invalid token." });
      return;
    }
  } catch (error) {
    logger.error(error);
    res.status(503).json({ message: "Service unavailable." });
    return;
  }
  next();
};
