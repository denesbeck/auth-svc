import { Result, ValidationError } from "express-validator";

export const validationErrorResponse = (errors: Result<ValidationError>) => {
  const messages = errors.array().map((el) => el.msg);
  return messages.join(". ") + (messages.length > 1 ? "." : "");
};
