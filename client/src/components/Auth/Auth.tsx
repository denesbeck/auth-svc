import { Routes, Route } from "react-router-dom";
import Login from "./Login";
import Register from "./Register";
import { RegisterProvider } from "../../contexts/RegisterContext";

const Auth = () => {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route
        path="/register"
        element={
          <RegisterProvider>
            <Register />
          </RegisterProvider>
        }
      />
    </Routes>
  );
};

export default Auth;
