import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],

  // Keep REACT_APP_ prefix so we don't need to rename env vars in source files.
  // Access them as import.meta.env.REACT_APP_* in code.
  envPrefix: "REACT_APP_",

  build: {
    outDir: "build",       // match CRA default so CI/deploy scripts don't change
    sourcemap: false,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // Manual chunk splitting to keep individual chunks small
        manualChunks: {
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-mui": ["@mui/material", "@mui/icons-material"],
          "vendor-query": ["@tanstack/react-query"],
          "vendor-msal": ["@azure/msal-react", "@azure/msal-browser"],
          "vendor-charts": ["recharts"],
          "vendor-flow": ["reactflow"],
        },
      },
    },
  },

  resolve: {
    alias: {
      // Allow absolute imports from src/
      "@": path.resolve(__dirname, "src"),
    },
  },

  server: {
    port: 3000,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
