import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // The node-threatlocker package is installed but not built (dist/ is absent).
      // Point to the stub so tests can import client.ts without a resolution error.
      '@wyre-ai/node-threatlocker': resolve(
        __dirname,
        'src/__tests__/__stubs__/node-threatlocker.ts',
      ),
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
