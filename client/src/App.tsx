import { ThemeProvider } from "@emotion/react";
import { Layout, Login } from "./components";
import { defaultTheme } from "./utils/theme";

function App() {
  return (
    <ThemeProvider theme={defaultTheme}>
      <Layout>
        <Login />
      </Layout>
    </ThemeProvider>
  );
}

export default App;
