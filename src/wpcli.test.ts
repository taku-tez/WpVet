/**
 * WP-CLI parser tests - v0.3.0
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { 
  parsePluginList, 
  parseThemeList, 
  parseWpCliInput,
  wpcliToDetectionResult,
  parseAndConvert,
} from './wpcli.js';

test('parsePluginList - valid array', () => {
  const input = [
    { name: 'akismet', version: '5.0', status: 'active', update: 'none', auto_update: 'on' },
    { name: 'jetpack', version: '12.0', status: 'inactive', update: 'available' },
  ];
  
  const plugins = parsePluginList(input);
  
  assert.strictEqual(plugins.length, 2);
  assert.strictEqual(plugins[0].slug, 'akismet');
  assert.strictEqual(plugins[0].version, '5.0');
  assert.strictEqual(plugins[0].status, 'active');
  assert.strictEqual(plugins[0].update, 'none');
  assert.strictEqual(plugins[0].auto_update, 'on');
  assert.strictEqual(plugins[1].update, 'available');
});

test('parsePluginList - empty array', () => {
  const plugins = parsePluginList([]);
  assert.strictEqual(plugins.length, 0);
});

test('parsePluginList - throws on non-array', () => {
  assert.throws(() => parsePluginList({} as any), /Expected array/);
});

test('parseThemeList - valid array', () => {
  const input = [
    { name: 'flavor', version: '3.5', status: 'active', update: 'none', auto_update: 'off' },
    { name: 'flavor-developer', version: '3.4', status: 'parent' },
  ];
  
  const themes = parseThemeList(input);
  
  assert.strictEqual(themes.length, 2);
  assert.strictEqual(themes[0].slug, 'flavor');
  assert.strictEqual(themes[0].status, 'active');
  assert.strictEqual(themes[0].auto_update, 'off');
  assert.strictEqual(themes[1].status, 'parent');
});

test('parseWpCliInput - JSON object with plugins', () => {
  const input = JSON.stringify({
    core: { version: '6.4.2', site_url: 'https://example.com' },
    plugins: [{ name: 'akismet', version: '5.0', status: 'active' }],
    themes: [],
  });
  
  const { data, errors } = parseWpCliInput(input);
  
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(data.core?.version, '6.4.2');
  assert.strictEqual(data.core?.site_url, 'https://example.com');
  assert.strictEqual(data.plugins?.length, 1);
  assert.strictEqual(data.plugins?.[0].slug, 'akismet');
});

test('parseWpCliInput - JSON array (plugins)', () => {
  const input = JSON.stringify([
    { name: 'plugin1', version: '1.0', status: 'active' },
    { name: 'plugin2', version: '2.0', status: 'inactive' },
  ]);
  
  const { data, errors } = parseWpCliInput(input);
  
  assert.strictEqual(errors.length, 0);
  assert.strictEqual(data.plugins?.length, 2);
});

test('parseWpCliInput - NDJSON with errors', () => {
  const input = `{"name": "plugin1", "version": "1.0", "status": "active"}
invalid json line
{"name": "plugin2", "version": "2.0", "status": "active"}`;
  
  // Should parse valid lines and record errors
  const { data, errors } = parseWpCliInput(input);
  
  assert.ok(errors.length > 0);
  assert.strictEqual(errors[0].line, 2);
  assert.ok(errors[0].content.includes('invalid'));
});

test('parseWpCliInput - empty input throws', () => {
  assert.throws(() => parseWpCliInput(''), /Empty input/);
  assert.throws(() => parseWpCliInput('   \n  '), /Empty input/);
});

test('wpcliToDetectionResult - full conversion', () => {
  const input = {
    core: { version: '6.4.2', site_url: 'https://example.com', multisite: false },
    plugins: [
      { name: 'akismet', slug: 'akismet', version: '5.0', status: 'active' as const, update: 'available' as const },
    ],
    themes: [
      { name: 'flavor', slug: 'flavor', version: '3.5', status: 'active' as const },
    ],
  };
  
  const result = wpcliToDetectionResult(input, 'test-target');
  
  assert.strictEqual(result.target, 'test-target');
  assert.strictEqual(result.source, 'wp-cli');
  assert.strictEqual(result.core?.version, '6.4.2');
  assert.strictEqual(result.core?.confidence, 100);
  assert.strictEqual(result.plugins.length, 1);
  assert.strictEqual(result.plugins[0].update, 'available');
  assert.strictEqual(result.themes.length, 1);
  assert.ok(result.site?.site_url === 'https://example.com');
  assert.strictEqual(result.site?.multisite, false);
});

test('wpcliToDetectionResult - generates valid CPEs', () => {
  const input = {
    core: { version: '6.4.2' },
    plugins: [{ name: 'contact-form-7', slug: 'contact-form-7', version: '5.8', status: 'active' as const }],
    themes: [],
  };
  
  const result = wpcliToDetectionResult(input);
  
  assert.ok(result.core?.cpe.startsWith('cpe:2.3:a:wordpress:wordpress:'));
  assert.ok(result.plugins[0].cpe.includes(':contact-form-7:'));
  assert.ok(result.plugins[0].cpe.includes(':wordpress:'));
});

test('parseAndConvert - includes parse errors', () => {
  const input = `[{"name": "plugin1", "version": "1.0", "status": "active"}]
invalid line`;
  
  const result = parseAndConvert(input, 'test');
  
  // Should have parsed the valid plugin
  assert.strictEqual(result.plugins.length, 1);
  // Should have recorded the parse error
  assert.ok(result.errors.some(e => e.includes('Line 2')));
});

test('wpcliToDetectionResult - handles missing optional fields', () => {
  const input = {
    plugins: [{ name: 'minimal', slug: 'minimal', version: '1.0', status: 'active' as const }],
  };
  
  const result = wpcliToDetectionResult(input);
  
  assert.strictEqual(result.core, undefined);
  assert.strictEqual(result.plugins.length, 1);
  assert.strictEqual(result.themes.length, 0);
  assert.strictEqual(result.site, undefined);
});
