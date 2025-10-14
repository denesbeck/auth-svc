import { ThemeProvider } from "@emotion/react";
import { AlertBox, Layout, Login } from "./components";
import { defaultTheme } from "./utils/theme";

function App() {
  return (
    <ThemeProvider theme={defaultTheme}>
      <AlertBox context="global" />
      <Layout>
        <Login />
      </Layout>
    </ThemeProvider>
  );
}

export default App;
