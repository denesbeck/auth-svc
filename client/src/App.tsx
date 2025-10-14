import { ThemeProvider } from "@emotion/react";
import { AlertBox, Layout, Login } from "./components";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { defaultTheme } from "./utils/theme";

function App() {
  const queryClient = new QueryClient();

  return (
    <QueryClientProvider client={queryClient}>
      <ReactQueryDevtools initialIsOpen={false} client={queryClient} />
      <ThemeProvider theme={defaultTheme}>
        <AlertBox context="global" />
        <Layout>
          <Login />
        </Layout>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
