import { ThemeProvider } from "@emotion/react";
import { AlertBox, Auth, Layout } from "./components";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { defaultTheme } from "./utils/theme";
import { BrowserRouter as Router } from "react-router-dom";
import { useAuth } from "./hooks";

function App() {
  const queryClient = new QueryClient();
  const { isPending } = useAuth();

  if (isPending) return <div>Redirecting...</div>;
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
