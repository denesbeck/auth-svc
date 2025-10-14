import { InputAdornment, TextField } from "@mui/material";
import { Email, Key, CheckCircleOutline } from "@mui/icons-material";
import { useRegisterContext } from "../../contexts/RegisterContext";
import { useRegisterFormValidation } from "../../hooks";

export type IPassword = {
  password: string;
  confirmPassword: string;
};

const Credentials = () => {
  const { email, setEmail, password, setPassword } = useRegisterContext();
  const { formValidity } = useRegisterFormValidation();

  return (
    <>
      <TextField
        error={formValidity.email.invalid}
        helperText={formValidity.email.errorMessage}
        autoFocus
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
                  className={`${password.password.length >= 8 && password.password === password.confirmPassword && "text-teal-400"}`}
                />
              </InputAdornment>
            ),
          },
        }}
      />
    </>
  );
};

export default Credentials;
