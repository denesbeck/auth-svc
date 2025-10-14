import { useEffect, useState } from "react";
import { checkAuth } from "../actions/auth";

const useAuth = () => {
  const [isPending, setIsPending] = useState(true);

  const fetchProtectedData = async () => {
    const res = await checkAuth();

    if (res.success === true) {
      window.location.href = res.data?.redirectUrl as string;
    } else {
      setIsPending(false);
    }
  };
  useEffect(() => {
    fetchProtectedData();
  }, []);

  return { isPending };
};

export default useAuth;
