import { NextFunction, Request, Response } from "express";
import logger from "../utils/logger";

export const loggerMiddleware = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  logger.info(`${req.method} ${req.url}`);
  next();
};
