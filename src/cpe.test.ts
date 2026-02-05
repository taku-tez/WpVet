/**
 * CPE generation tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { generateCoreCpe, generatePluginCpe, generateThemeCpe, parseCpe } from './cpe.js';

test('generateCoreCpe', async (t) => {
  await t.test('generates valid WordPress core CPE', () => {
    const cpe = generateCoreCpe('6.4.2');
    assert.strictEqual(cpe, 'cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*');
  });

  await t.test('handles unknown version', () => {
    const cpe = generateCoreCpe('unknown');
    assert.strictEqual(cpe, 'cpe:2.3:a:wordpress:wordpress:unknown:*:*:*:*:*:*:*');
  });
});

test('generatePluginCpe', async (t) => {
  await t.test('generates valid plugin CPE', () => {
    const cpe = generatePluginCpe('contact-form-7', '5.7.1');
    assert.strictEqual(cpe, 'cpe:2.3:a:contact-form-7:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*');
  });

  await t.test('handles custom vendor', () => {
    const cpe = generatePluginCpe('elementor', '3.18.0', 'elementor');
    assert.strictEqual(cpe, 'cpe:2.3:a:elementor:elementor:3.18.0:*:*:*:*:wordpress:*:*');
  });

  await t.test('normalizes special characters', () => {
    const cpe = generatePluginCpe('my_plugin@test', '1.0.0');
    assert.ok(cpe.includes('my_plugin_test'));
  });
});

test('generateThemeCpe', async (t) => {
  await t.test('generates valid theme CPE', () => {
    const cpe = generateThemeCpe('twentytwentyfour', '1.0');
    assert.strictEqual(cpe, 'cpe:2.3:a:twentytwentyfour:twentytwentyfour:1.0:*:*:*:*:wordpress:*:*');
  });
});

test('parseCpe', async (t) => {
  await t.test('parses valid CPE string', () => {
    const result = parseCpe('cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*');
    assert.deepStrictEqual(result, {
      vendor: 'wordpress',
      product: 'wordpress',
      version: '6.4.2',
      targetSw: '*',
    });
  });

  await t.test('parses plugin CPE with target_sw', () => {
    const result = parseCpe('cpe:2.3:a:contact-form-7:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*');
    assert.deepStrictEqual(result, {
      vendor: 'contact-form-7',
      product: 'contact-form-7',
      version: '5.7.1',
      targetSw: 'wordpress',
    });
  });

  await t.test('returns null for invalid CPE', () => {
    const result = parseCpe('invalid');
    assert.strictEqual(result, null);
  });
});
