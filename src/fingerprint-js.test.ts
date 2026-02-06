/**
 * Tests for JS fingerprint detection
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  calculateHash,
  normalizeJsContent,
  detectCoreByJsFingerprint,
  detectPluginFromJs,
  extractPluginVersionsFromVerParam,
  detectPluginsFromJsPaths,
} from './fingerprint-js.js';
import { DEFAULT_OPTIONS, type ScanOptions } from './types.js';

describe('calculateHash', () => {
  it('should calculate SHA-256 hash of content', () => {
    const content = 'console.log("hello");';
    const hash = calculateHash(content);
    
    assert.strictEqual(typeof hash, 'string');
    assert.strictEqual(hash.length, 64); // SHA-256 hex is 64 chars
  });
  
  it('should produce consistent hashes', () => {
    const content = 'const x = 1;';
    const hash1 = calculateHash(content);
    const hash2 = calculateHash(content);
    
    assert.strictEqual(hash1, hash2);
  });
  
  it('should produce different hashes for different content', () => {
    const hash1 = calculateHash('const x = 1;');
    const hash2 = calculateHash('const x = 2;');
    
    assert.notStrictEqual(hash1, hash2);
  });
});

describe('normalizeJsContent', () => {
  it('should remove BOM', () => {
    const contentWithBom = '\uFEFFconsole.log("test");';
    const normalized = normalizeJsContent(contentWithBom);
    
    assert.strictEqual(normalized, 'console.log("test");');
  });
  
  it('should normalize CRLF to LF', () => {
    const content = 'line1\r\nline2\r\nline3';
    const normalized = normalizeJsContent(content);
    
    assert.strictEqual(normalized, 'line1\nline2\nline3');
  });
  
  it('should normalize CR to LF', () => {
    const content = 'line1\rline2\rline3';
    const normalized = normalizeJsContent(content);
    
    assert.strictEqual(normalized, 'line1\nline2\nline3');
  });
  
  it('should trim whitespace', () => {
    const content = '  \n  console.log("test");  \n  ';
    const normalized = normalizeJsContent(content);
    
    assert.strictEqual(normalized, 'console.log("test");');
  });
  
  it('should handle mixed line endings and BOM', () => {
    const content = '\uFEFF  \r\nline1\rline2\r\nline3  \n';
    const normalized = normalizeJsContent(content);
    
    assert.strictEqual(normalized, 'line1\nline2\nline3');
  });
});

describe('extractPluginVersionsFromVerParam', () => {
  it('should extract plugin versions from ?ver= parameters', () => {
    const html = `
      <script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0"></script>
      <script src="/wp-content/plugins/woocommerce/assets/js/frontend.min.js?ver=8.5.1"></script>
      <link href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.9.2" />
    `;
    
    const versions = extractPluginVersionsFromVerParam(html);
    
    assert.strictEqual(versions.get('elementor'), '3.18.0');
    assert.strictEqual(versions.get('woocommerce'), '8.5.1');
    assert.strictEqual(versions.get('contact-form-7'), '5.9.2');
  });
  
  it('should handle multiple files from same plugin', () => {
    const html = `
      <script src="/wp-content/plugins/jetpack/_inc/build/photon/photon.min.js?ver=13.1"></script>
      <script src="/wp-content/plugins/jetpack/_inc/build/likes/loading.min.js?ver=13.1.1"></script>
    `;
    
    const versions = extractPluginVersionsFromVerParam(html);
    
    // Should keep the longer (more specific) version
    assert.strictEqual(versions.get('jetpack'), '13.1.1');
  });
  
  it('should return empty map for no matches', () => {
    const html = '<html><body>No WordPress here</body></html>';
    
    const versions = extractPluginVersionsFromVerParam(html);
    
    assert.strictEqual(versions.size, 0);
  });
  
  it('should handle case-insensitive paths', () => {
    const html = `
      <script src="/WP-CONTENT/plugins/some-plugin/js/main.js?ver=1.2.3"></script>
    `;
    
    const versions = extractPluginVersionsFromVerParam(html);
    
    assert.strictEqual(versions.get('some-plugin'), '1.2.3');
  });
});

describe('detectPluginsFromJsPaths', () => {
  it('should detect known plugins from JS paths', () => {
    const html = `
      <script src="/wp-content/plugins/elementor/assets/js/frontend.min.js"></script>
      <script src="/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js"></script>
    `;
    
    const plugins = detectPluginsFromJsPaths(html);
    
    assert.ok(plugins.has('elementor'));
    assert.ok(plugins.has('woocommerce'));
  });
  
  it('should return empty set for unknown plugins', () => {
    const html = `
      <script src="/wp-content/plugins/unknown-plugin/js/main.js"></script>
    `;
    
    const plugins = detectPluginsFromJsPaths(html);
    
    assert.strictEqual(plugins.size, 0);
  });
});

// Integration-style tests with mocked fetch
describe('detectCoreByJsFingerprint (mocked)', () => {
  const originalFetch = globalThis.fetch;
  
  beforeEach(() => {
    // Mock fetch - use any type to avoid complex type compatibility issues
    globalThis.fetch = (async (url: URL | RequestInfo) => {
      const urlStr = url.toString();
      if (urlStr.includes('jquery-migrate.min.js')) {
        return {
          ok: true,
          headers: new Map([['content-type', 'application/javascript']]),
          text: async () => '/*! jQuery Migrate 3.4.1 - WordPress v6.7 */\nconsole.log("migrate");',
        } as unknown as Response;
      }
      if (urlStr.includes('wp-emoji-release.min.js')) {
        return {
          ok: true,
          headers: new Map([['content-type', 'application/javascript']]),
          text: async () => '/* @version 6.7 */\nwindow.wpEmoji = {};',
        } as unknown as Response;
      }
      return { ok: false } as Response;
    }) as typeof fetch;
  });
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  
  it('should extract version from JS comments', async () => {
    const options: ScanOptions = { ...DEFAULT_OPTIONS, timeout: 5000 };
    
    const result = await detectCoreByJsFingerprint('https://example.com', options);
    
    // Should find version 6.7 from the mock
    assert.strictEqual(result.source, 'js-fingerprint');
    assert.ok(result.matches.length > 0);
  });
});

describe('detectPluginFromJs (mocked)', () => {
  const originalFetch = globalThis.fetch;
  
  beforeEach(() => {
    // Mock fetch - use any type to avoid complex type compatibility issues
    globalThis.fetch = (async (url: URL | RequestInfo) => {
      const urlStr = url.toString();
      if (urlStr.includes('elementor/assets/js/frontend.min.js')) {
        return {
          ok: true,
          headers: new Map([['content-type', 'application/javascript']]),
          text: async () => '/*! elementor - v3.18.0 - 2024-01-15 */\n(function(){})();',
        } as unknown as Response;
      }
      if (urlStr.includes('woocommerce/assets/js/frontend/woocommerce.min.js')) {
        return {
          ok: true,
          headers: new Map([['content-type', 'application/javascript']]),
          text: async () => '/*! WooCommerce v8.5.1 */\njQuery(function($){});',
        } as unknown as Response;
      }
      return { ok: false } as Response;
    }) as typeof fetch;
  });
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  
  it('should detect Elementor version from JS', async () => {
    const options: ScanOptions = { ...DEFAULT_OPTIONS, timeout: 5000 };
    
    const result = await detectPluginFromJs('https://example.com', 'elementor', options);
    
    assert.notStrictEqual(result, null);
    assert.strictEqual(result?.plugin, 'elementor');
    assert.strictEqual(result?.version, '3.18.0');
    assert.strictEqual(result?.confidence, 80);
  });
  
  it('should detect WooCommerce version from JS', async () => {
    const options: ScanOptions = { ...DEFAULT_OPTIONS, timeout: 5000 };
    
    const result = await detectPluginFromJs('https://example.com', 'woocommerce', options);
    
    assert.notStrictEqual(result, null);
    assert.strictEqual(result?.plugin, 'woocommerce');
    assert.strictEqual(result?.version, '8.5.1');
  });
  
  it('should return null for unknown plugin with no JS', async () => {
    const options: ScanOptions = { ...DEFAULT_OPTIONS, timeout: 5000 };
    
    const result = await detectPluginFromJs('https://example.com', 'nonexistent-plugin', options);
    
    assert.strictEqual(result, null);
  });
});
