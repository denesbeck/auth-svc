import { Button, InputAdornment, TextField } from "@mui/material";
import Header from "./Header";
import Modal from "./Modal";
import {
  RocketLaunch,
  Email,
  Key,
  CheckCircleOutline,
} from "@mui/icons-material";
import { useState } from "react";
import { Info } from ".";

type IPassword = {
  password: string;
  confirmPassword: string;
};

interface IRegister {
  close: () => void;
}

const Register = ({ close }: IRegister) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState({
    password: "",
    confirmPassword: "",
  });

  const handleNext = () => {
    console.log("next");
  };

  return (
    <Modal close={close}>
      <Header
        title="Register"
        icon={RocketLaunch}
        backgroundColor="bg-red-300"
      />
      <Info text="Fill in the form below to get started with your new account." />
      <div className="flex flex-col gap-4 animate-textFocus">
        <TextField
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

        <div className="flex justify-end">
          <Button color="primary" variant="contained" onClick={handleNext}>
            Next
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default Register;
