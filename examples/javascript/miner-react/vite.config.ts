import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const appDir = fileURLToPath(new URL(".", import.meta.url));
const beeSdkPkgDir = fileURLToPath(new URL("../../../bee_sdk/pkg", import.meta.url));

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      allow: [appDir, beeSdkPkgDir],
    },
  },
});
