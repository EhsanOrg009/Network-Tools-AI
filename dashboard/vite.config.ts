import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The FastAPI core serves the built SPA at /dashboard (single port).
// In development `npm run dev` proxies API calls to the backend.
export default defineConfig({
  plugins: [react()],
  base: "/dashboard/",
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
