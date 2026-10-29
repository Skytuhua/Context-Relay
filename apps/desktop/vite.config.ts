import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';
import { devCspPlugin } from './dev-csp-plugin';

export default defineConfig({
  plugins: [react(), devCspPlugin],
  server: { port: 1420, strictPort: true },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test-setup.ts',
  },
});
