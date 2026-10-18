import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
declare const process: { env: Record<string, string | undefined> };
export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PEASO_UI_PORT || 5173),
    proxy: {
      "/api": {
        target: process.env.PEASO_API_ORIGIN || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  build: { chunkSizeWarningLimit: 1800 },
});
