import { Button, InputAdornment, TextField } from "@mui/material";
import { Email, Key, CheckCircleOutline } from "@mui/icons-material";
import { useRegisterContext } from "../../contexts/RegisterContext";
import { useAlert, useRegisterFormValidation } from "../../hooks";
import { register } from "../../actions/auth";
import { useMutation } from "@tanstack/react-query";

export type IPassword = {
  password: string;
  confirmPassword: string;
};

interface ICredentials {
  next: () => void;
}

const Credentials = ({ next }: ICredentials) => {
  const { email, setEmail, password, setPassword } = useRegisterContext();
  const { formValidity, validateForm } = useRegisterFormValidation();
  const { alert } = useAlert("global");

  const { mutateAsync, isPending } = useMutation({
    mutationKey: ["register"],
    mutationFn: () => {
      return register({ email, password: password.password });
    },
  });

  const handleNext = async () => {
    const isFormValid = validateForm();
    if (!isFormValid) return;

    const res = await mutateAsync();
    if (res.success !== true) {
      alert({
        id: "register-error",
        message: res.message,
        severity: "error",
      });
      return;
    } else {
      alert({
        id: "register-success",
        message: "User successfully registered.",
        severity: "success",
      });
    }
    next();
  };

  return (
    <>
      <TextField
        error={formValidity.email.invalid}
        helperText={formValidity.email.errorMessage}
        autoFocus
        disabled={isPending}
        label="Email"
        variant="outlined"
        value={email}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          setEmail(event.target.value)
        }
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <Email />
              </InputAdornment>
            ),
          },
        }}
      />
      <TextField
        error={formValidity.password.invalid}
        helperText={formValidity.password.errorMessage}
        disabled={isPending}
        label="Password"
        type="password"
        variant="outlined"
        value={password.password}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          setPassword((prevState: IPassword) => ({
            ...prevState,
            password: event.target.value,
          }))
        }
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <Key />
              </InputAdornment>
            ),
          },
        }}
      />
      <TextField
        error={formValidity.confirmPassword.invalid}
        helperText={formValidity.confirmPassword.errorMessage}
        disabled={isPending}
        label="Confirm Password"
        type="password"
        variant="outlined"
        value={password.confirmPassword}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          setPassword((prevState: IPassword) => ({
            ...prevState,
            confirmPassword: event.target.value,
          }))
        }
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <CheckCircleOutline
                  className={`${password.password.length >= 8 && password.password === password.confirmPassword ? "text-teal-400" : ""}`}
                />
              </InputAdornment>
            ),
          },
        }}
      />
      <div className="flex gap-4 justify-end">
        <Button
          loading={isPending}
          color="primary"
          variant="contained"
          onClick={handleNext}
        >
          Next
        </Button>
      </div>
    </>
  );
};

export default Credentials;
