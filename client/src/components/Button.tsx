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
    "primary-solid": "bg-blue-400 text-white",
    "primary-outline":
      "text-blue-300 border hover:bg-blue-300/30 hover:text-blue-200 hover:border-blue-200  border-blue-300",
    "secondary-solid": "bg-dark-400 text-white",
    "secondary-outline":
      "text-dark-200 border hover:bg-dark-200/30 hover:text-dark-50 hover:border-dark-50 border-dark-200",
  };

  return (
    <div
      className={`flex relative justify-center items-center ${wide ? "" : "w-32"}`}
    >
      <button
        disabled={loading || disabled}
        onClick={action}
        className={`flex ${wide ? "w-full" : "w-max"} min-w-32 cursor-pointer items-center justify-center rounded-full disabled:brightness-50 disabled:grayscale ${VARIANTS[variant]} px-4 py-2 text-lg shadow-md transition-all duration-150 ease-in-out enabled:hover:brightness-110`}
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
