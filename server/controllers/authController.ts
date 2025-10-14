import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import postgres from "../lib/postgres";
import redis from "../lib/redis";
import crypto from "crypto";

const pgClient = postgres().getInstance();
const redisClient = redis().getInstance();

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  let salt, password_hash;
  try {
    const { rows } = await pgClient.query(
      `SELECT salt, password_hash FROM users WHERE email = $1`,
      [username],
    );
    if (rows.length === 0) {
      res.status(401).json({ message: "Invalid credentials." });
      return;
    }
    salt = rows[0].salt;
    password_hash = rows[0].password_hash;
  } catch (error) {
    console.error(error);
    res.status(503).json({ message: "Unable to login." });
    return;
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(salt + password)
    .digest("hex");

  if (password_hash === hashedPassword) {
    const token = jwt.sign(
      { username },
      process.env.JWT_SECRET || "jwt_secret",
      { expiresIn: "4h" },
    );
    await redisClient.set(username, token);
    await redisClient.expire(username, 60 * 60 * 4);
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials." });
  }
};

export const register = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const salt = crypto.randomBytes(32).toString("hex");
  const hashedPassword = crypto
    .createHash("sha256")
    .update(salt + password)
    .digest("hex");

  try {
    await pgClient.query(
      `INSERT INTO users (email, salt, password_hash) VALUES ($1, $2, $3);`,
      [username, salt, hashedPassword],
    );
  } catch (error) {
    if (error.code === "23505" && error.detail.includes("already exists")) {
      res.status(409).json({ message: "Email already registered." });
      return;
    }
    console.error(error);
    res.status(503).json({ message: "Unable to register." });
  }
  res.status(200).json({ message: "ok" });
};
