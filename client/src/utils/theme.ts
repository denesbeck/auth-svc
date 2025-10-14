import { createTheme } from "@mui/material/styles";

export const defaultTheme = createTheme({
  components: {
    MuiAlert: {
      styleOverrides: {
        filledSuccess: {
          backgroundColor: "#5ee9b5",
          color: "black",
        },
        filledError: {
          backgroundColor: "#ffa2a2",
          color: "black",
        },
        filledWarning: {
          backgroundColor: "#ffb86a",
          color: "black",
        },
        filledInfo: {
          backgroundColor: "#8ec5ff",
          color: "black",
        },
      },
    },
  },
});
