import type { Plugin } from 'vite';

// This transform does not use the Vite hook context. Declaring it separately
// keeps that contract explicit when the production function is tested directly.
function transformDevCsp(html: string) {
  return html.replace(
    /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/,
    (_match, open, policy: string, close) =>
      `${open}${policy.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")}${close}`,
  );
}

// Vite injects styles at runtime during development. Keep this relaxation in a
// serve-only plugin so index.html and the packaged production policy stay strict.
export const devCspPlugin = {
  name: 'context-relay-dev-csp',
  apply: 'serve' as const,
  transformIndexHtml: transformDevCsp,
} satisfies Plugin;
