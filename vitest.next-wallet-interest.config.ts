import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = path.dirname(fileURLToPath(import.meta.url));

/** Bridge: next-wallet interest goldens against local SDK sources (pre-release). */
export default defineConfig({
  test: {
    include: ["../conceal-next-wallet/tests/interest.test.ts"],
  },
  resolve: {
    alias: {
      "conceal-wallet-sdk": path.resolve(root, "src/index.ts"),
    },
  },
});
