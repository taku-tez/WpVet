/**
 * Tests for misconfiguration detection
 */

import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { runMisconfigChecks, runAudit, MISCONFIG_CHECKS } from './misconfig.js';
import { runPluginVulnChecks, runAllPluginVulnChecks, PLUGIN_VULN_CHECKS } from './plugin-vulns.js';
import { DEFAULT_OPTIONS, type ScanOptions, type DetectedComponent } from './types.js';

// Mock fetch for testing
const originalFetch = globalThis.fetch;

function createMockFetch(responses: Map<string, { status: number; body: string }>) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    
    for (const [pattern, response] of responses) {
      if (url.includes(pattern)) {
        return new Response(response.body, {
          status: response.status,
          headers: { 'Content-Type': 'text/html' },
        });
      }
    }
    
    // Default 404
    return new Response('Not Found', { status: 404 });
  };
}

describe('Misconfiguration Checks', () => {
  const testOptions: ScanOptions = {
    ...DEFAULT_OPTIONS,
    timeout: 5000,
  };
  
  beforeEach(() => {
    // Reset fetch mock before each test
  });
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  
  it('should have expected number of checks', () => {
    assert.ok(MISCONFIG_CHECKS.length >= 10, 'Should have at least 10 misconfiguration checks');
  });
  
  it('should detect exposed wp-config.php', async () => {
    const responses = new Map([
      ['wp-config.php', { status: 200, body: "<?php define('DB_NAME', 'wordpress'); define('DB_USER', 'root');" }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const wpConfigResult = results.find(r => r.id === 'wp-config-exposed');
    
    assert.ok(wpConfigResult, 'Should detect exposed wp-config.php');
    assert.strictEqual(wpConfigResult?.severity, 'critical');
  });
  
  it('should detect debug mode enabled', async () => {
    const responses = new Map([
      ['example.com', { status: 200, body: '<html>Fatal error: Uncaught Error on line 42</html>' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const debugResult = results.find(r => r.id === 'debug-mode-enabled');
    
    assert.ok(debugResult, 'Should detect debug mode');
    assert.strictEqual(debugResult?.severity, 'high');
  });
  
  it('should detect directory listing', async () => {
    const responses = new Map([
      ['wp-content/uploads/', { status: 200, body: '<html><title>Index of /wp-content/uploads/</title>Parent Directory</html>' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const dirListResult = results.find(r => r.id === 'directory-listing');
    
    assert.ok(dirListResult, 'Should detect directory listing');
    assert.strictEqual(dirListResult?.severity, 'medium');
  });
  
  it('should detect XML-RPC enabled', async () => {
    const responses = new Map([
      ['xmlrpc.php', { 
        status: 200, 
        body: `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>wp.getUsersBlogs</string></value>
            <value><string>wp.newPost</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>` 
      }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const xmlrpcResult = results.find(r => r.id === 'xmlrpc-enabled');
    
    assert.ok(xmlrpcResult, 'Should detect XML-RPC enabled');
    assert.strictEqual(xmlrpcResult?.severity, 'medium');
  });
  
  it('should detect readme.html exposure', async () => {
    const responses = new Map([
      ['readme.html', { status: 200, body: '<html>WordPress Version 6.4.2</html>' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const readmeResult = results.find(r => r.id === 'readme-exposed');
    
    assert.ok(readmeResult, 'Should detect readme.html');
    assert.strictEqual(readmeResult?.severity, 'low');
  });
  
  it('should detect user enumeration via REST API', async () => {
    const responses = new Map([
      ['wp-json/wp/v2/users', { status: 200, body: '[{"id":1,"slug":"admin","name":"Administrator"}]' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const userEnumResult = results.find(r => r.id === 'user-enumeration');
    
    assert.ok(userEnumResult, 'Should detect user enumeration');
    assert.strictEqual(userEnumResult?.severity, 'medium');
  });
  
  it('should detect debug log exposure', async () => {
    const responses = new Map([
      ['wp-content/debug.log', { status: 200, body: '[15-Jan-2024 10:30:00] PHP Warning: something' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    const debugLogResult = results.find(r => r.id === 'debug-log-exposed');
    
    assert.ok(debugLogResult, 'Should detect debug log exposure');
    assert.strictEqual(debugLogResult?.severity, 'high');
  });
  
  it('should return empty array when no issues found', async () => {
    // All 404s
    globalThis.fetch = createMockFetch(new Map());
    
    const results = await runMisconfigChecks('https://secure-example.com', testOptions);
    assert.strictEqual(results.length, 0, 'Should find no issues on secure site');
  });
  
  it('should sort results by severity', async () => {
    const responses = new Map([
      ['wp-config.php', { status: 200, body: "define('DB_NAME', 'wp');" }],
      ['readme.html', { status: 200, body: 'WordPress Version 6.4' }],
      ['wp-json/wp/v2/users', { status: 200, body: '[{"slug":"admin"}]' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runMisconfigChecks('https://example.com', testOptions);
    
    if (results.length >= 2) {
      const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
      for (let i = 1; i < results.length; i++) {
        const prevIndex = severityOrder.indexOf(results[i - 1].severity);
        const currIndex = severityOrder.indexOf(results[i].severity);
        assert.ok(prevIndex <= currIndex, 'Results should be sorted by severity');
      }
    }
  });
});

describe('Plugin Vulnerability Checks', () => {
  const testOptions: ScanOptions = {
    ...DEFAULT_OPTIONS,
    timeout: 5000,
  };
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  
  it('should have expected number of plugin checks', () => {
    assert.ok(PLUGIN_VULN_CHECKS.length >= 7, 'Should have at least 7 plugin vulnerability checks');
  });
  
  it('should detect WooCommerce API exposure', async () => {
    const responses = new Map([
      ['wp-json/wc/v3/orders', { status: 200, body: '[{"id":1,"status":"completed","total":"99.99"}]' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const plugins: DetectedComponent[] = [
      { type: 'plugin', slug: 'woocommerce', name: 'WooCommerce', version: '8.0.0', cpe: '', confidence: 100, source: 'remote' }
    ];
    
    const results = await runPluginVulnChecks('https://example.com', plugins, testOptions);
    const wooResult = results.find(r => r.id === 'woo-api-exposure');
    
    assert.ok(wooResult, 'Should detect WooCommerce API exposure');
    assert.strictEqual(wooResult?.severity, 'critical');
  });
  
  it('should detect UpdraftPlus backup exposure', async () => {
    const responses = new Map([
      ['wp-content/updraft/', { status: 200, body: '<html>Index of /wp-content/updraft/<a href="backup_2024.zip">backup_2024.zip</a></html>' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const plugins: DetectedComponent[] = [
      { type: 'plugin', slug: 'updraftplus', name: 'UpdraftPlus', version: '1.0.0', cpe: '', confidence: 100, source: 'remote' }
    ];
    
    const results = await runPluginVulnChecks('https://example.com', plugins, testOptions);
    const updraftResult = results.find(r => r.id === 'updraft-backup-exposure');
    
    assert.ok(updraftResult, 'Should detect UpdraftPlus backup exposure');
    assert.strictEqual(updraftResult?.severity, 'critical');
  });
  
  it('should skip checks for plugins not installed', async () => {
    const responses = new Map([
      ['wp-json/wc/v3/orders', { status: 200, body: '[{"id":1}]' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    // No WooCommerce in plugins list
    const plugins: DetectedComponent[] = [
      { type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', version: '5.0.0', cpe: '', confidence: 100, source: 'remote' }
    ];
    
    const results = await runPluginVulnChecks('https://example.com', plugins, testOptions);
    const wooResult = results.find(r => r.id === 'woo-api-exposure');
    
    assert.ok(!wooResult, 'Should not check for WooCommerce vulnerabilities when not installed');
  });
  
  it('should run all plugin checks in comprehensive mode', async () => {
    const responses = new Map([
      ['wp-json/wc/v3/orders', { status: 200, body: '[{"id":1}]' }],
      ['wp-content/updraft/', { status: 200, body: 'Index of backup_' }],
    ]);
    globalThis.fetch = createMockFetch(responses);
    
    const results = await runAllPluginVulnChecks('https://example.com', testOptions);
    
    // Should run all checks regardless of detected plugins
    assert.ok(results.length >= 2, 'Should find multiple vulnerabilities in comprehensive mode');
  });
});

describe('Audit Result', () => {
  const testOptions: ScanOptions = {
    ...DEFAULT_OPTIONS,
    timeout: 5000,
  };
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });
  
  it('should return complete audit result', async () => {
    globalThis.fetch = createMockFetch(new Map());
    
    const result = await runAudit('https://example.com', testOptions);
    
    assert.ok(result.target, 'Should have target');
    assert.ok(result.timestamp, 'Should have timestamp');
    assert.ok(Array.isArray(result.misconfigs), 'Should have misconfigs array');
    assert.ok(Array.isArray(result.pluginVulns), 'Should have pluginVulns array');
    assert.ok(Array.isArray(result.errors), 'Should have errors array');
  });
});
