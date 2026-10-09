import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@wallet/fonts.css";
import "@wallet/index.css";
import "./ext.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
