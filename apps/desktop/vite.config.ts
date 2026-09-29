import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// index.html carries a Content-Security-Policy meta tag so that a plain static
// host still gets a policy. Vite injects styles at runtime during `vite dev`,
// which `style-src 'self'` blocks, leaving the dev server rendering unstyled.
// Relax style-src for the dev server only; the meta tag is left untouched so the
// production policy is unchanged, and tauri.conf.json still supplies a real
// header for the packaged app.
const devCspPlugin = {
  name: 'context-relay-dev-csp',
  apply: 'serve' as const,
  transformIndexHtml(html: string) {
    return html.replace(
      /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/,
      (_match, open, policy: string, close) =>
        `${open}${policy.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")}${close}`,
    );
  },
};

export default defineConfig({
  plugins: [react(), devCspPlugin],
  test: {
    environment: 'jsdom',
    setupFiles: './src/test-setup.ts',
  },
});
