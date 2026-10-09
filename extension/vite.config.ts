// Built from the wallet's dependency tree: `npm run build` in extension/
// invokes vite from ../wallet so that react, viem and the hash libraries
// resolve to one copy for the wallet's components and this entry. The
// config therefore loads its own imports relative to ../wallet as well.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
import { cpSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const wallet = resolve(here, "../wallet");
const mods = resolve(wallet, "node_modules");
const req = createRequire(resolve(wallet, "package.json"));
const react = (req("@vitejs/plugin-react").default ?? req("@vitejs/plugin-react")) as () => unknown;
const dist = resolve(here, "dist");

// The wallet's stylesheet references its self-hosted fonts at /fonts/…,
// which inside an extension page resolves to chrome-extension://<id>/fonts/….
const fonts = {
  name: "aegis-copy-fonts",
  apply: "build",
  closeBundle() { cpSync(resolve(wallet, "public/fonts"), resolve(dist, "fonts"), { recursive: true }); },
};

export default {
  root: here,
  base: "./",
  plugins: [react(), fonts],
  resolve: {
    alias: {
      "@wallet": resolve(wallet, "src"),
      react: resolve(mods, "react"),
      "react-dom": resolve(mods, "react-dom"),
      viem: resolve(mods, "viem"),
      "@scure/bip39": resolve(mods, "@scure/bip39"),
    },
    dedupe: ["react", "react-dom", "viem"],
  },
  build: {
    target: "es2022",
    outDir: dist,
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        index: resolve(here, "index.html"),
        background: resolve(here, "src/background.ts"),
      },
      output: {
        // The service worker must be a stable, un-hashed file name for the manifest.
        entryFileNames: (c: { name: string }) => (c.name === "background" ? "background.js" : "assets/[name]-[hash].js"),
      },
    },
  },
  worker: { format: "es" },
};
