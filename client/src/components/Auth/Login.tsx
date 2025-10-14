import { InputAdornment, TextField } from "@mui/material";
import { Button } from "../../components";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import { useState } from "react";
import { IAuthAction, login } from "../../actions/auth";
import { useAlert } from "../../hooks";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { alert } = useAlert("global");
  const navigate = useNavigate();

  const { mutateAsync, isPending } = useMutation({
    mutationKey: ["login"],
    mutationFn: ({ email, password }: IAuthAction) =>
      login({ email, password }),
  });

  const handleLogin = async () => {
    const res = await mutateAsync({ email, password });
    if (res.success === true) {
      window.location.href = res.data?.redirectUrl as string;
    } else {
      alert({
        id: "login",
        message: res.message as string,
        severity: "error",
      });
    }
  };

  return (
    <div className="flex flex-col gap-8 justify-center items-center py-10 w-screen shadow-2xl animate-slide-in-from-bottom bg-dark-800 min-h-[45vh] sm:rounded-4xl sm:min-w-[35rem] sm:max-w-[35vw] sm:w-[90vw]">
      <div className="flex flex-col gap-2 items-center">
        <h1 className="text-4xl font-semibold text-transparent bg-clip-text from-indigo-500 via-blue-300 to-indigo-400 bg-linear-to-tr">
          Welcome back!
        </h1>

        <p className="text-lg text-center sm:whitespace-nowrap text-dark-100">
          Please login to your account to continue.
        </p>
      </div>
      <TextField
        // suppressHydrationWarning={true}
        disabled={isPending}
        label="Email"
        variant="outlined"
        className="w-[80%]"
        value={email}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          setEmail(event.target.value)
        }
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <EmailIcon />
              </InputAdornment>
            ),
          },
        }}
      />
      <TextField
        label="Password"
        disabled={isPending}
        type="password"
        variant="outlined"
        className="mb-2 w-[80%]"
        value={password}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          setPassword(() => event.target.value)
        }
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <LockIcon />
              </InputAdornment>
            ),
          },
        }}
      />
      <div className="grid grid-cols-2 gap-4 w-[80%]">
        <Button
          loading={isPending}
          disabled={isPending}
          icon={<VpnKeyIcon className="mr-2" />}
          action={handleLogin}
          variant="primary-outline"
          label="Login"
          wide={true}
        />
        <Button
          disabled={isPending}
          icon={<RocketLaunchIcon className="mr-2" />}
          action={() => navigate("/register")}
          variant="secondary-outline"
          label="Register"
          wide={true}
        />
      </div>
    </div>
  );
};

export default Login;
