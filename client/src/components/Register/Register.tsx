import { RocketLaunch } from "@mui/icons-material";
import { Header, Info, Modal } from "..";
import { Credentials } from ".";
import { useStepper } from "../../hooks";

interface IRegister {
  close: () => void;
}

const Register = ({ close }: IRegister) => {
  const { step, next, back } = useStepper();

  return (
    <Modal close={close}>
      <Header
        title="Register"
        icon={RocketLaunch}
        backgroundColor="bg-red-300"
      />
      <Info text="Fill in the form below to get started with your new account." />
      <div className="flex flex-col gap-4 animate-textFocus">
        {step === 1 && <Credentials next={next} />}
      </div>
    </Modal>
  );
};

export default Register;
