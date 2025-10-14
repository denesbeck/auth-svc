import { isAxiosError } from "axios";
import mainService from "../services/mainService";

export interface IAuthAction {
  email: string;
  password: string;
}

type AuthResponse = {
  success: boolean;
  message?: string;
  data?: { redirectUrl?: string };
};

export const login = async ({
  email,
  password,
}: IAuthAction): Promise<AuthResponse> => {
  try {
    const { data } = await mainService.post("/v1/auth/login", {
      email,
      password,
    });
    return { success: true, data };
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

export const checkAuth = async (): Promise<AuthResponse> => {
  try {
    const res = await mainService.get("/v1/check-auth");
    return {
      success: res.status === 200,
      message: res.data.message,
      data: { redirectUrl: res.data.redirectUrl },
    };
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
