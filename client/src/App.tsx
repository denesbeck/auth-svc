import { ThemeProvider } from "@emotion/react";
import { AlertBox, Auth, Layout } from "./components";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { defaultTheme } from "./utils/theme";
import { BrowserRouter as Router } from "react-router-dom";

function App() {
  const queryClient = new QueryClient();

  return (
    <Router>
      <QueryClientProvider client={queryClient}>
        <ReactQueryDevtools initialIsOpen={false} client={queryClient} />
        <ThemeProvider theme={defaultTheme}>
          <AlertBox context="global" />
          <Layout>
            <Auth />
          </Layout>
        </ThemeProvider>
      </QueryClientProvider>
    </Router>
  );
}

export default App;
