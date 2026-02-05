/**
 * WP-CLI parser tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parseWpCliInput, wpcliToDetectionResult } from './wpcli.js';

test('parseWpCliInput', async (t) => {
  await t.test('parses plugin array', () => {
    const input = JSON.stringify([
      { name: 'akismet', version: '5.3', status: 'active' },
      { name: 'jetpack', version: '12.8', status: 'inactive' },
    ]);
    const result = parseWpCliInput(input);
    assert.strictEqual(result.plugins?.length, 2);
    assert.strictEqual(result.plugins?.[0].slug, 'akismet');
    assert.strictEqual(result.plugins?.[0].version, '5.3');
  });

  await t.test('parses combined object', () => {
    const input = JSON.stringify({
      core: { version: '6.4.2' },
      plugins: [{ name: 'akismet', version: '5.3', status: 'active' }],
      themes: [{ name: 'twentytwentyfour', version: '1.0', status: 'active' }],
    });
    const result = parseWpCliInput(input);
    assert.strictEqual(result.core?.version, '6.4.2');
    assert.strictEqual(result.plugins?.length, 1);
    assert.strictEqual(result.themes?.length, 1);
  });

  await t.test('throws on empty input', () => {
    assert.throws(() => parseWpCliInput(''), /Empty input/);
  });
});

test('wpcliToDetectionResult', async (t) => {
  await t.test('converts to detection result with CPEs', () => {
    const input = {
      core: { version: '6.4.2' },
      plugins: [{ name: 'akismet', slug: 'akismet', version: '5.3', status: 'active' as const }],
      themes: [],
    };
    const result = wpcliToDetectionResult(input, 'test');
    
    assert.strictEqual(result.source, 'wp-cli');
    assert.strictEqual(result.core?.version, '6.4.2');
    assert.strictEqual(result.core?.cpe, 'cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*');
    assert.strictEqual(result.plugins.length, 1);
    assert.strictEqual(result.plugins[0].confidence, 100);
  });
});
