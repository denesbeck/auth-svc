import { useState } from "react";

const useRegisterFormValidation = () => {
  const [formValidity, setFormValidity] = useState({
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

  return {
    formValidity,
  };
};

export default useRegisterFormValidation;
