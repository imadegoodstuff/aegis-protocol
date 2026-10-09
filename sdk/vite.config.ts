import { defineConfig } from "vite";

// Library build: one ES module, every runtime dependency left external.
// The sources are the wallet's own client (../wallet/src/aegis), so the SDK
// and the site can never disagree about a byte.
export default defineConfig({
  build: {
    target: "es2022",
    sourcemap: true,
    minify: false,
    lib: { entry: "src/index.ts", formats: ["es"], fileName: () => "index.js" },
    rollupOptions: {
      external: [/^viem/, /^@noble\//, /^@scure\//, "hash-wasm", /^node:/],
    },
  },
});
