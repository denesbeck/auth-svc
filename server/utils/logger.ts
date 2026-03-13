import chalk from "chalk";
import { format } from "date-fns";

function formatArgs(args: any[]): string {
  return args
    .map((el) => (typeof el === "string" ? el : JSON.stringify(el)))
    .join(" ");
}

export default {
  error: (...args: any[]) => {
    console.error(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.red(" [ERROR] ") +
        formatArgs(args),
    );
  },
  warn: (...args: any[]) =>
    console.warn(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.yellow(" [WARN] ") +
        formatArgs(args),
    ),
  debug: (...args: any[]) =>
    Boolean(process.env.DEBUG) &&
    console.debug(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.blue(" [DEBUG] ") +
        formatArgs(args),
    ),
  info: (...args: any[]) =>
    console.info(
      chalk.dim(format(new Date(), "yyyy-MM-dd HH:mm:ss")) +
        chalk.cyan(" [INFO] ") +
        formatArgs(args),
    ),
};
