import { Totp, generateBackupCodes } from "time2fa";
import crypto from "crypto";

export const generate = (user: string) => {
  const key = Totp.generateKey({
    issuer: "csync",
    user,
  });
  return key;
};

export const validate = (secret: string, passcode: string) => {
  return Totp.validate({
    secret,
    passcode,
  });
};

export const getBackupCodes = () =>
  generateBackupCodes().map((backupCode) =>
    crypto
      .createHash("sha256")
      .update(backupCode)
      .digest("hex")
      .slice(0, 12)
      .toUpperCase()
      .replace(/(\w{4})(\w{4})(\w{4})/, "$1-$2-$3"),
  );
