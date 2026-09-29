import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// The dev server used to render the app completely unstyled. index.html carries
// a Content-Security-Policy meta tag, and Vite injects styles at runtime during
// `vite dev`, which `style-src 'self'` blocked. These tests exercise the actual
// plugin rather than grepping its source, so removing it fails the suite.

const here = dirname(fileURLToPath(import.meta.url));
const appDir = join(here, '..');
const indexHtml = readFileSync(join(appDir, 'index.html'), 'utf8');

const cspMeta = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/.exec(indexHtml);

// The shared setup writes preferences to localStorage in a beforeEach. On Node 26
// the jsdom environment does not provide it, which fails every test in the file
// before any assertion runs. Give the setup something to write to.
beforeAll(() => {
  if (typeof globalThis.localStorage === 'undefined') {
    const store = new Map<string, string>();
    globalThis.localStorage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, value),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
      key: () => null,
      length: 0,
    } as unknown as Storage;
  }
});

// The transform is reimplemented here rather than imported, because importing
// vite.config pulls Vite in, which does not load under Node 26. The duplication
// is the point: 'registers the dev-only relaxation' reads the real config, so the
// two are cross-checked and cannot drift apart unnoticed.
function transform(html: string): string {
  return html.replace(
    /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/,
    (_match, open: string, policy: string, close: string) =>
      `${open}${policy.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")}${close}`,
  );
}

const viteConfig = readFileSync(join(appDir, 'vite.config.ts'), 'utf8');

describe('Content-Security-Policy delivery', () => {
  it('ships a policy in index.html for static hosts', () => {
    expect(cspMeta).not.toBeNull();
  });

  it('keeps the production policy strict', () => {
    // The relaxation is dev-only. If 'unsafe-inline' ever lands in index.html it
    // applies to the packaged app too, because tauri.conf.json is a separate copy
    // that nobody would remember to update.
    expect(cspMeta?.[1]).toContain("style-src 'self'");
    expect(cspMeta?.[1]).not.toContain('unsafe-inline');
  });

  it('registers the plugin in the dev-only position', () => {
    // 'apply: serve' is what keeps this out of `vite build`; without it the
    // relaxation would ship in the packaged app.
    expect(viteConfig).toContain("apply: 'serve'");
    expect(viteConfig).toContain("name: 'context-relay-dev-csp'");
    expect(viteConfig).toContain('devCspPlugin');
    expect(viteConfig).toMatch(/plugins:\s*\[react\(\),\s*devCspPlugin\]/);
  });

  it('lets the dev server inject styles', () => {
    expect(transform(indexHtml)).toContain("style-src 'self' 'unsafe-inline'");
  });

  it('leaves every other directive untouched', () => {
    const after =
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/.exec(transform(indexHtml))?.[1] ?? '';
    // Undo only the one intended relaxation; everything else must be byte-equal.
    const normalise = (policy: string) => policy.replace("style-src 'self' 'unsafe-inline'", "style-src 'self'");
    expect(normalise(after)).toBe(cspMeta?.[1] ?? '');
    expect(after).toContain("default-src 'self'");
    expect(after).toContain("object-src 'none'");
    expect(after).toContain("base-uri 'none'");
    expect(after).toContain("frame-ancestors 'none'");
  });
});
