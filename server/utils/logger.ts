import chalk from "chalk";
import { format } from "date-fns";

export default {
  error: (...args: any[]) => {
    console.error(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.red(" [ERROR] ") +
        args
          .map((el) => JSON.stringify(el))
          .join(" ")
          .slice(1, -1),
    );
  },
  warn: (...args: any[]) =>
    console.warn(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.yellow(" [WARN] ") +
        args
          .map((el) => JSON.stringify(el))
          .join(" ")
          .slice(1, -1),
    ),
  debug: (...args: any[]) =>
    Boolean(process.env.DEBUG) &&
    console.debug(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.blue(" [DEBUG] ") +
        args
          .map((el) => JSON.stringify(el))
          .join(" ")
          .slice(1, -1),
    ),
  info: (...args: any[]) =>
    console.info(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.cyan(" [INFO] ") +
        args
          .map((el) => JSON.stringify(el))
          .join(" ")
          .slice(1, -1),
    ),
};
