import { RocketLaunch } from "@mui/icons-material";
import { Header, Info, Modal } from "..";
import { Credentials } from ".";
import { useStepper } from "../../hooks";

interface IRegister {
  close: () => void;
}

const Register = ({ close }: IRegister) => {
  const { step, next } = useStepper();

  return (
    <div className="flex z-10 flex-col gap-8 justify-center items-center py-10 w-screen shadow-2xl bg-black/60 backdrop-blur-xs min-h-[45vh] sm:rounded-4xl sm:min-w-[35rem] sm:max-w-[35vw] sm:w-[90vw]">
      <Header
        title="Register"
        icon={RocketLaunch}
        backgroundColor="bg-red-300"
      />
      <Info text="Fill in the form below to get started with your new account." />
      <div className="flex flex-col gap-4 animate-textFocus">
        {step === 1 && <Credentials next={next} />}
      </div>
    </div>
  );
};

export default Register;
