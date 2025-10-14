import { useState } from "react";

const useStepper = (min: number = 1, max: number = 3, start: number = 1) => {
  const [step, setStep] = useState(start);

  const back = () => {
    if (step === min) return;
    setStep((prev) => prev - 1);
  };

  const next = () => {
    if (step === max) return;
    setStep((prev) => prev + 1);
  };

  return {
    step,
    back,
    next,
  };
};

export default useStepper;
