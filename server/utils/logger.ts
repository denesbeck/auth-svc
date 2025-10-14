import chalk from "chalk";
import { format } from "date-fns";

export default {
  error: (message: string) =>
    console.error(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
      chalk.red(" [ERROR] ") +
      message,
    ),
  warn: (message: string) =>
    console.warn(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
      chalk.yellow(" [WARN] ") +
      message,
    ),
  debug: (message: string) =>
    Boolean(process.env.DEBUG) &&
    console.debug(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
      chalk.blue(" [DEBUG] ") +
      message,
    ),
  info: (message: string) =>
    console.info(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
      chalk.cyan(" [INFO] ") +
      message,
    ),
};
