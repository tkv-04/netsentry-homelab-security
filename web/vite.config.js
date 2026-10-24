import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: resolve(projectRoot, "../src/netsentry/dashboard"),
    emptyOutDir: true,
    assetsDir: "assets",
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8090" },
  },
});
