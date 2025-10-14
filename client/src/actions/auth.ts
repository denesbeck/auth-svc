import { isAxiosError } from "axios";
import mainService from "../services/mainService";

interface ILoginAction {
  email: string;
  password: string;
}

type LoginResult = { success: true } | { success: false; message: string };

export const login = async ({
  email,
  password,
}: ILoginAction): Promise<LoginResult> => {
  try {
    await mainService.post("/v1/auth/login", {
      email,
      password,
    });
    return { success: true };
  } catch (e: unknown) {
    let message = "An unknown error occurred";
    if (isAxiosError(e)) {
      message = e.response?.data?.message;
    }

    return {
      success: false,
      message: message,
    };
  }
};
