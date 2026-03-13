import chalk from "chalk";
import { format } from "date-fns";

/**
 * Safely formats log arguments. Error objects are sanitized to prevent
 * leaking sensitive information (connection strings, query params, etc.).
 */
function formatArgs(args: any[]): string {
  return args
    .map((el) => {
      if (el instanceof Error) {
        // Only log message and a truncated stack — never the full error object
        // which may contain query details, connection strings, etc.
        const stack =
          process.env.NODE_ENV !== "production" && el.stack
            ? `\n${el.stack.split("\n").slice(0, 5).join("\n")}`
            : "";
        return `${el.name}: ${el.message}${stack}`;
      }
      if (typeof el === "string") return el;
      // For non-Error objects, stringify but truncate to prevent log flooding
      try {
        const str = JSON.stringify(el);
        return str.length > 500 ? str.slice(0, 500) + "...[truncated]" : str;
      } catch {
        return "[unserializable]";
      }
    })
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
    process.env.DEBUG === "true" &&
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
