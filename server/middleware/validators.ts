import { body } from "express-validator";

const MIN_PWD_LEN = Number(process.env.MIN_PWD_LEN) || 6;

export const authValidator = [
  body("email").isEmail().withMessage("Email must be valid"),
  body("password")
    .isLength({ min: MIN_PWD_LEN })
    .withMessage(`Password must be at least ${MIN_PWD_LEN} characters long`),
];
