import { createPortal } from "react-dom";
import { ReactElement, useEffect, useState } from "react";

interface BackdropProps {
  children: ReactElement;
  id?: string;
}

const Backdrop = ({ children, id }: BackdropProps) => {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);
  if (!mounted) return null;
  return createPortal(
    <div
      id={id}
      className="flex overflow-y-auto fixed top-0 left-0 justify-center items-center py-8 w-screen h-screen z-1350 bg-slate-900/80 backdrop-blur-xs"
    >
      {children}
    </div>,
    document.body,
  );
};

export default Backdrop;
