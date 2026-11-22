import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In development the dashboard runs on http://localhost:5173 and forwards /api/* to the
// FastAPI server, so the browser only ever talks to one origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  test: {
    environment: "jsdom",
  },
});
