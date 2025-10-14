import { useEffect } from "react";
import { Severity } from "./AlertBox";
import { Alert as MuiAlert } from "@mui/material";

interface IAlert {
  message: string;
  severity: Severity;
  duration?: number;
  close: () => void;
}

const Alert = ({ message, severity, duration = 5000, close }: IAlert) => {
  useEffect(() => {
    const timeout = setTimeout(() => {
      close();
    }, duration);
    return () => {
      clearTimeout(timeout);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <MuiAlert
      className="w-max animate-text-focus"
      severity={severity}
      variant="filled"
      onClose={close}
    >
      {message}
    </MuiAlert>
  );
};

export default Alert;
