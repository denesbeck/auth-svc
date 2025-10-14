import React, { useState, useMemo, ReactNode } from "react";
import { createContext, useContext, Dispatch, SetStateAction } from "react";

export interface IPassword {
  password: string;
  confirmPassword: string;
}

export interface IRegisterContext {
  email: string;
  setEmail: Dispatch<SetStateAction<string>>;
  password: IPassword;
  setPassword: Dispatch<SetStateAction<IPassword>>;
  confirmationCode: string;
  setConfirmationCode: Dispatch<SetStateAction<string>>;
}

const RegisterContext = createContext<IRegisterContext | undefined>(undefined);

const RegisterProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<IPassword>({
    password: "",
    confirmPassword: "",
  });
  const [confirmationCode, setConfirmationCode] = useState<string>("");

  const value = useMemo(
    () => ({
      email,
      setEmail,
      password,
      setPassword,
      confirmationCode,
      setConfirmationCode,
    }),
    [email, password, confirmationCode],
  );

  return (
    <RegisterContext.Provider value={value}>
      {children}
    </RegisterContext.Provider>
  );
};

const useRegisterContext = () => {
  const context = useContext(RegisterContext);

  if (!context) {
    throw new Error(
      "useRegisterContext must be used within a RegisterProvider",
    );
  }

  return context;
};

// eslint-disable-next-line react-refresh/only-export-components
export { RegisterProvider, useRegisterContext };
