import jwt, { JwtPayload } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import redis from "../lib/redis";

const redisClient = redis().getInstance();

export const jwtAuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    res.status(401).json({ message: "Access denied. No token provided." });
    return;
  }

  let username;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    username = (decoded as JwtPayload)?.username;
  } catch (error) {
    console.error("Invalid token.");
    res.status(401).json({ message: "Access denied. Invalid token." });
    return;
  }

  if (!username) {
    console.error("Username missing.");
    res.status(401).json({ message: "Access denied. Invalid token." });
    return;
  }

  try {
    const redisToken = await redisClient.get(username);
    if (redisToken !== token) {
      console.error("Token mismatch.");
      res.status(401).json({ message: "Access denied. Invalid token." });
      return;
    }
  } catch (error) {
    console.error(error);
    res.status(503).json({ message: "Service unavailable." });
    return;
  }
  next();
};
