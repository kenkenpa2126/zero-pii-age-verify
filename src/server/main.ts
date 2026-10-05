import { serve } from "@hono/node-server";
import { app } from "./index.ts";
import { store } from "./store.ts";

await store.init();

const port = Number(process.env.PORT ?? 8787);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`zero-pii demo: http://localhost:${info.port}  (wallet: /wallet.html, shop: /shop.html)`);
});
