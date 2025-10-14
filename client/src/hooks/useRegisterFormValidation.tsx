import { useCallback, useState } from "react";
import { isEmail, isStrongPassword } from "validator";
import { useRegisterContext } from "../contexts/RegisterContext";

interface FieldValidity {
  invalid: boolean;
  errorMessage: string;
}

interface FormValidity {
  email: FieldValidity;
  password: FieldValidity;
  confirmPassword: FieldValidity;
}

const useRegisterFormValidation = () => {
  const { email, password } = useRegisterContext();

  const [formValidity, setFormValidity] = useState<FormValidity>({
    email: {
      invalid: false,
      errorMessage: "",
    },
    password: {
      invalid: false,
      errorMessage: "",
    },
    confirmPassword: {
      invalid: false,
      errorMessage: "",
    },
  });

  const validateForm = useCallback(() => {
    const emailValid = isEmail(email);
    const passwordValid = isStrongPassword(password.password);
    const confirmPasswordValid = password.password === password.confirmPassword;

    setFormValidity({
      email: {
        invalid: !emailValid,
        errorMessage: !emailValid ? "Invalid email format." : "",
      },
      password: {
        invalid: !passwordValid,
        errorMessage: !passwordValid
          ? "Password must be at least 8 characters long and include 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol."
          : "",
      },
      confirmPassword: {
        invalid: !confirmPasswordValid,
        errorMessage: !confirmPasswordValid ? "Password doesn't match." : "",
      },
    });

    return emailValid && passwordValid && confirmPasswordValid;
  }, [email, password.password, password.confirmPassword]);

  return {
    formValidity,
    validateForm,
  };
};

export default useRegisterFormValidation;
