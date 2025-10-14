import { isAxiosError } from "axios";
import mainService from "../services/mainService";

export interface IAuthAction {
  email: string;
  password: string;
}

type AuthResponse = { success: true } | { success: false; message: string };

export const login = async ({
  email,
  password,
}: IAuthAction): Promise<AuthResponse> => {
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

export const register = async ({
  email,
  password,
}: IAuthAction): Promise<AuthResponse> => {
  try {
    await mainService.post("/v1/auth/register", {
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
