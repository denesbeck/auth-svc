import { useEffect, useState } from "react";
import { Alert } from ".";
import { ThemeProvider } from "@mui/material/styles";
import { defaultTheme } from "../utils/theme";

export type Severity = "error" | "warning" | "info" | "success";

export interface IAlertPayload {
  id: string;
  message: string;
  severity: Severity;
  duration?: number;
}

interface IAlertBox {
  maxAlert?: number;
  context?: string;
}

const AlertBox = ({ maxAlert = 5, context = "" }: IAlertBox) => {
  const [alerts, setAlerts] = useState<IAlertPayload[]>([]);

  useEffect(() => {
    function handleAlert(event: CustomEvent) {
      const alertEventDetail = event.detail as IAlertPayload;
      if (alerts.find((alert) => alert.id === alertEventDetail.id)) return;
      setAlerts((prev) => {
        return [alertEventDetail, ...prev].slice(0, maxAlert);
      });
    }
    function handleCloseAlert(event: CustomEvent) {
      const alertEventDetail = event.detail as IAlertPayload;
      setAlerts((prev) =>
        prev.filter((alert) => alert.id !== alertEventDetail.id),
      );
    }
    function handlePurgeAlerts() {
      setAlerts([]);
    }

    // @ts-expect-error: https://github.com/microsoft/TypeScript/issues/28357
    window.addEventListener(
      `${context.length ? context + "/" : ""}alert-event`,
      handleAlert,
    );
    // @ts-expect-error: https://github.com/microsoft/TypeScript/issues/28357
    window.addEventListener(
      `${context.length ? context + "/" : ""}close-alert`,
      handleCloseAlert,
    );
    window.addEventListener(
      `${context.length ? context + "/" : ""}purge-alerts`,
      handlePurgeAlerts,
    );
    return () => {
      // @ts-expect-error: https://github.com/microsoft/TypeScript/issues/28357
      window.removeEventListener(
        `${context.length ? context + "/" : ""}alert-event`,
        handleAlert,
      );
      // @ts-expect-error: https://github.com/microsoft/TypeScript/issues/28357
      window.removeEventListener(
        `${context.length ? context + "/" : ""}close-alert`,
        handleCloseAlert,
      );
      window.removeEventListener(
        `${context.length ? context + "/" : ""}purge-alerts`,
        handlePurgeAlerts,
      );
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts]);

  return (
    <ThemeProvider theme={defaultTheme}>
      <div className="flex fixed top-2 right-2 z-10 flex-col items-end space-y-2 w-max">
        {alerts.map((el) => {
          return (
            <Alert
              key={el.id}
              severity={el.severity}
              message={el.message}
              close={() =>
                setAlerts((prev) => prev.filter((alert) => alert.id !== el.id))
              }
            />
          );
        })}
      </div>
    </ThemeProvider>
  );
};

export default AlertBox;
