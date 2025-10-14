import { RocketLaunch } from "@mui/icons-material";
import { Header, Info } from "../..";
import Credentials from "./Credentials";

const Register = () => {
  return (
    <div className="flex flex-col justify-center py-10 px-10 w-screen shadow-2xl bg-black/60 backdrop-blur-xs min-h-[45vh] sm:rounded-4xl sm:min-w-[35rem] sm:max-w-[35vw] sm:w-[90vw]">
      <Header
        title="Register"
        icon={RocketLaunch}
        backgroundColor="bg-red-300"
      />
      <Info text="Fill in the form below to get started with your new account." />
      <div className="flex flex-col gap-4 animate-textFocus">
        <Credentials />
      </div>
    </div>
  );
};

export default Register;
