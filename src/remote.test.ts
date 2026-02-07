import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanRemote } from './remote.js';
import { DEFAULT_OPTIONS } from './types.js';

describe('remote version extraction', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = (async (url: URL | RequestInfo) => {
      const urlStr = url.toString();

      if (urlStr === 'https://example.com') {
        return {
          ok: true,
          status: 200,
          text: async () => `
            <html>
              <head>
                <meta name="generator" content="WordPress 6.7.1" />
                <link rel="stylesheet" href="/wp-content/themes/test-theme/style.css" />
              </head>
              <body>
                <script src="/wp-content/plugins/test-plugin/assets/main.js"></script>
              </body>
            </html>
          `,
        } as Response;
      }

      if (urlStr.endsWith('/wp-content/plugins/test-plugin/readme.txt')) {
        return {
          ok: true,
          status: 200,
          text: async () => '=== Test Plugin ===\nVersion: 1.2.3-beta\n',
        } as Response;
      }

      if (urlStr.endsWith('/wp-content/themes/test-theme/style.css')) {
        return {
          ok: true,
          status: 200,
          text: async () => 'Theme Name: Test Theme\nVersion: 1.2.3-beta\n',
        } as Response;
      }

      return {
        ok: false,
        status: 404,
        text: async () => '',
        json: async () => ({}),
      } as Response;
    }) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('extracts pre-release versions from readme.txt and style.css', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'wpvet-'));
    const configPath = join(tempDir, 'config.json');

    writeFileSync(
      configPath,
      JSON.stringify({ customPlugins: ['test-plugin'], customThemes: ['test-theme'] })
    );

    const result = await scanRemote('https://example.com', {
      ...DEFAULT_OPTIONS,
      retry: 0,
      fingerprint: false,
      configPath,
    });

    rmSync(tempDir, { recursive: true, force: true });

    const plugin = result.plugins.find(p => p.slug === 'test-plugin');
    const theme = result.themes.find(t => t.slug === 'test-theme');

    assert.ok(plugin);
    assert.ok(theme);
    assert.strictEqual(plugin?.version, '1.2.3-beta');
    assert.strictEqual(theme?.version, '1.2.3-beta');
  });
});
