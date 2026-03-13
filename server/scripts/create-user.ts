/**
 * CLI script to create a user in the database.
 *
 * Usage: npx ts-node scripts/create-user.ts <email> <password>
 */
import dotenv from "dotenv";

dotenv.config();

import bcrypt from "bcrypt";
import { getPool } from "../lib/postgres";

const SALT_ROUNDS = 12;

async function main() {
  const [email, password] = process.argv.slice(2);

  if (!email || !password) {
    console.error("Usage: npx ts-node scripts/create-user.ts <email> <password>");
    process.exit(1);
  }

  const pool = getPool();
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at`,
      [email, passwordHash],
    );
    console.log("User created:", rows[0]);
  } catch (error: any) {
    if (error.code === "23505") {
      console.error(`User with email '${email}' already exists.`);
    } else {
      console.error("Failed to create user:", error);
    }
    process.exit(1);
  }

  await pool.end();
}

main();
