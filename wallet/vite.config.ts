import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    target: "es2022",
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the heavy crypto deps and lazy UI chunks for better caching
        manualChunks(id) {
          if (id.includes("node_modules/@noble") || id.includes("node_modules/@scure")) return "crypto";
          if (id.includes("node_modules/react-dom")) return "react-dom";
          if (id.includes("node_modules/react/") || id.includes("node_modules/scheduler")) return "react";
        },
      },
    },
  },
});
