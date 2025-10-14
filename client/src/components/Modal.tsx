import { IconButton } from "@mui/material";
import { Backdrop } from ".";
import { useClickOutside } from "../hooks";
import CloseIcon from "@mui/icons-material/Close";

interface IModal {
  children: React.ReactNode;
  close?: () => void;
  keepOpen?: boolean;
}

const Modal = ({ children, close, keepOpen = true }: IModal) => {
  const ref = useClickOutside<HTMLDivElement>(close ? () => close() : () => {});

  return (
    <Backdrop>
      <div
        ref={keepOpen ? undefined : ref}
        className="flex relative flex-col p-8 bg-white rounded-2xl w-[30rem] max-w-[90vw] animate-slide-in-from-bottom text-neutral-600"
      >
        {close && (
          <div className="absolute top-0 right-0 p-2">
            <IconButton onClick={close}>
              <CloseIcon />
            </IconButton>
          </div>
        )}
        {children}
      </div>
    </Backdrop>
  );
};

export default Modal;
