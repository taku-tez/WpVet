/**
 * CPE generation tests - v0.3.0
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { 
  generateCoreCpe, 
  generatePluginCpe, 
  generateThemeCpe,
  parseCpe,
  isWordPressCpe,
  getVendorForPlugin,
} from './cpe.js';

test('generateCoreCpe - standard version', () => {
  const cpe = generateCoreCpe('6.4.2');
  assert.strictEqual(cpe, 'cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*');
});

test('generateCoreCpe - unknown version', () => {
  const cpe = generateCoreCpe('unknown');
  assert.strictEqual(cpe, 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*');
});

test('generateCoreCpe - version with special characters', () => {
  const cpe = generateCoreCpe('6.4.2-beta1');
  // Hyphen is allowed, no escaping needed
  assert.ok(cpe.includes('6.4.2-beta1'));
});

test('generatePluginCpe - known vendor', () => {
  const cpe = generatePluginCpe('contact-form-7', '5.8.1');
  // Should use known vendor "rocklobster"
  assert.ok(cpe.includes(':rocklobster:'));
  assert.ok(cpe.includes(':contact-form-7:'));
  assert.ok(cpe.includes(':5.8.1:'));
  assert.ok(cpe.includes(':wordpress:'));
});

test('generatePluginCpe - unknown vendor', () => {
  const cpe = generatePluginCpe('my-custom-plugin', '1.0.0');
  // Should fall back to using slug as vendor
  assert.ok(cpe.includes(':my-custom-plugin:'));
});

test('generatePluginCpe - custom vendor override', () => {
  const cpe = generatePluginCpe('some-plugin', '1.0.0', 'my-company');
  assert.ok(cpe.includes(':my-company:'));
});

test('generatePluginCpe - escapes special characters', () => {
  const cpe = generatePluginCpe('plugin', '1.0?beta*');
  assert.ok(cpe.includes('1.0\\?beta\\*'));
});

test('generateThemeCpe - standard theme', () => {
  const cpe = generateThemeCpe('flavor', '2.0.0');
  assert.ok(cpe.includes(':flavor:'));
  assert.ok(cpe.includes(':2.0.0:'));
  assert.ok(cpe.includes(':wordpress:'));
});

test('parseCpe - WordPress core', () => {
  const parsed = parseCpe('cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*');
  assert.deepStrictEqual(parsed, {
    vendor: 'wordpress',
    product: 'wordpress',
    version: '6.4.2',
    targetSw: '*',
  });
});

test('parseCpe - WordPress plugin', () => {
  const parsed = parseCpe('cpe:2.3:a:rocklobster:contact-form-7:5.8.1:*:*:*:*:wordpress:*:*');
  assert.deepStrictEqual(parsed, {
    vendor: 'rocklobster',
    product: 'contact-form-7',
    version: '5.8.1',
    targetSw: 'wordpress',
  });
});

test('parseCpe - escaped characters', () => {
  const cpe = 'cpe:2.3:a:vendor:product:1.0\\?beta:*:*:*:*:*:*:*';
  const parsed = parseCpe(cpe);
  assert.strictEqual(parsed?.version, '1.0?beta');
});


test('parseCpe - escaped colons round-trip', () => {
  const vendor = 'ven:dor';
  const product = 'pro:duct';
  const version = '1.2:3';
  const cpe = `cpe:2.3:a:${vendor.replace(/:/g, '\\:')}:${product.replace(/:/g, '\\:')}:${version.replace(/:/g, '\\:')}:*:*:*:*:wordpress:*:*`;
  const parsed = parseCpe(cpe);

  assert.deepStrictEqual(parsed, {
    vendor,
    product,
    version,
    targetSw: 'wordpress',
  });
});

test('parseCpe - unknown version (*)', () => {
  const parsed = parseCpe('cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*');
  assert.strictEqual(parsed?.version, 'unknown');
});

test('parseCpe - invalid CPE returns null', () => {
  const parsed = parseCpe('not-a-cpe');
  assert.strictEqual(parsed, null);
});

test('isWordPressCpe - core', () => {
  assert.strictEqual(
    isWordPressCpe('cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*'),
    true
  );
});

test('isWordPressCpe - plugin with wordpress target_sw', () => {
  assert.strictEqual(
    isWordPressCpe('cpe:2.3:a:vendor:plugin:1.0:*:*:*:*:wordpress:*:*'),
    true
  );
});

test('isWordPressCpe - non-WordPress', () => {
  assert.strictEqual(
    isWordPressCpe('cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*'),
    false
  );
});

test('getVendorForPlugin - known plugin', () => {
  assert.strictEqual(getVendorForPlugin('woocommerce'), 'automattic');
  assert.strictEqual(getVendorForPlugin('contact-form-7'), 'rocklobster');
});

test('getVendorForPlugin - unknown plugin returns slug', () => {
  assert.strictEqual(getVendorForPlugin('my-unknown-plugin'), 'my-unknown-plugin');
});

test('normalization - special characters in slug', () => {
  const cpe = generatePluginCpe('My Plugin!@#$', '1.0');
  // Should normalize to lowercase with underscores
  assert.ok(cpe.includes(':my_plugin'));
});
