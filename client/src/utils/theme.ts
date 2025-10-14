import { blue, cyan, indigo, pink, teal } from "@mui/material/colors";
import { createTheme } from "@mui/material/styles";

export const defaultTheme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: blue[300],
      contrastText: "#fff",
    },
    secondary: {
      main: indigo[300],
      contrastText: "#fff",
    },
    info: {
      main: cyan[300],
      contrastText: "#fff",
    },
    error: {
      main: pink[300],
      contrastText: "#fff",
    },
    success: {
      main: teal[300],
      contrastText: "#fff",
    },
  },
});

export const alertTheme = createTheme({
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
