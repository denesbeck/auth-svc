import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

export const jwtAuthMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    res.status(401).json({ message: "Access denied. No token provided." });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwt_secret");
    console.log(decoded);
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token." });
  }
};
