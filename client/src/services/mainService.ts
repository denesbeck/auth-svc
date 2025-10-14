import axios from "axios";

const isDev = import.meta.env.MODE === "development";

const axiosInstance = axios.create({
  baseURL: isDev ? "http://localhost:4001/api" : "/api",
  withCredentials: true,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
  },
});

export default axiosInstance;
