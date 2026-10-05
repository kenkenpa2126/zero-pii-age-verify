import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: { "/api": "http://localhost:8787" },
  },
  build: {
    outDir: "public",
    emptyOutDir: true,
    rollupOptions: {
      input: { wallet: "wallet.html", shop: "shop.html" },
    },
  },
});
