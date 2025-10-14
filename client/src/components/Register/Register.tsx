import { Button } from "@mui/material";
import { RocketLaunch } from "@mui/icons-material";
import { Header, Info, Modal } from "..";
import { Credentials } from ".";
import { useAlert, useStepper } from "../../hooks";
import { register } from "../../actions/auth";
import { useRegisterContext } from "../../contexts/RegisterContext";

interface IRegister {
  close: () => void;
}

const Register = ({ close }: IRegister) => {
  const { step, next, back } = useStepper();
  const { email, password } = useRegisterContext();
  const { alert } = useAlert();

  const handleNext = async () => {
    const res = await register({ email, password: password.password });
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
    <Modal close={close}>
      <Header
        title="Register"
        icon={RocketLaunch}
        backgroundColor="bg-red-300"
      />
      <Info text="Fill in the form below to get started with your new account." />
      <div className="flex flex-col gap-4 animate-textFocus">
        {step === 1 && <Credentials />}
        <div className="flex gap-4 justify-end">
          {step > 1 && (
            <Button color="primary" variant="outlined" onClick={back}>
              Back
            </Button>
          )}
          <Button color="primary" variant="contained" onClick={handleNext}>
            Next
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default Register;
