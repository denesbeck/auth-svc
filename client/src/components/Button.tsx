import { CircularProgress } from "@mui/material";
import { ReactElement } from "react";

interface ButtonProps {
  variant:
    | "primary-solid"
    | "primary-outline"
    | "secondary-solid"
    | "secondary-outline";
  label: string;
  action: () => void;
  icon?: ReactElement;
  iconPosition?: "left" | "right";
  wide?: boolean;
  loading?: boolean;
  disabled?: boolean;
}

const Button = ({
  variant = "primary-solid",
  label,
  action,
  icon,
  iconPosition = "left",
  wide = false,
  loading = false,
  disabled = false,
}: ButtonProps) => {
  const VARIANTS = {
    "primary-solid": "bg-cyan-500 text-white",
    "primary-outline":
      "text-cyan-400 border hover:bg-cyan-500/30 hover:text-cyan-300 hover:border-cyan-300  border-cyan-400",
    "secondary-solid": "bg-slate-400 text-white",
    "secondary-outline":
      "text-slate-300 border hover:bg-slate-300/30 hover:text-slate-100 hover:border-slate-100 border-slate-300",
  };

  return (
    <div className="flex relative justify-center items-center">
      <button
        disabled={loading || disabled}
        onClick={action}
        className={`flex ${wide ? "w-full" : "w-max"} cursor-pointer items-center justify-center rounded-full disabled:brightness-50 disabled:grayscale ${VARIANTS[variant]} px-4 py-2 text-lg shadow-md transition-all duration-150 ease-in-out enabled:hover:brightness-110`}
      >
        {iconPosition === "left" && icon}
        <span>{label}</span>
        {iconPosition === "right" && icon}
      </button>
      {loading && (
        <CircularProgress
          className="absolute text-blue-400"
          size={30}
          thickness={5}
        />
      )}
    </div>
  );
};

export default Button;
