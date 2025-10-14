import { InputAdornment, TextField } from "@mui/material";
import { Button } from "@/components";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import { useState } from "react";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <div className="flex z-10 flex-col gap-8 justify-center items-center py-10 w-screen bg-white shadow-2xl min-h-[45vh] sm:rounded-4xl sm:min-w-[35rem] sm:max-w-[35vw] sm:w-[90vw]">
      <div className="flex flex-col gap-2 items-center">
        <h1 className="text-4xl font-semibold text-transparent bg-clip-text from-cyan-300 via-indigo-500 to-blue-400 bg-linear-to-tr">
          Welcome back!
        </h1>

        <p className="text-lg text-center sm:whitespace-nowrap text-slate-400">
          Please login to your account to continue.
        </p>
      </div>
      <TextField
        suppressHydrationWarning={true}
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
          icon={<VpnKeyIcon className="mr-2" />}
          action={() => console.log("Login")}
          variant="primary-solid"
          label="Login"
          wide={true}
        />
        <Button
          icon={<RocketLaunchIcon className="mr-2" />}
          action={() => console.log("Login")}
          variant="secondary-outline"
          label="Register"
          wide={true}
        />
      </div>
    </div>
  );
};

export default Login;
