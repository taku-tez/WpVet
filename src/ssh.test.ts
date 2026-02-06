/**
 * SSH module tests
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parseSshUrl } from './ssh.js';

test('parseSshUrl', async (t) => {
  await t.test('parses full SSH URL', () => {
    const config = parseSshUrl('ssh://deploy@example.com:2222/var/www/wordpress');
    assert.strictEqual(config.user, 'deploy');
    assert.strictEqual(config.host, 'example.com');
    assert.strictEqual(config.port, 2222);
    assert.strictEqual(config.wpPath, '/var/www/wordpress');
    assert.strictEqual(config.wpPathEscaped, '\'/var/www/wordpress\'');
  });

  await t.test('parses SSH URL without user', () => {
    const config = parseSshUrl('ssh://server.com/var/www/html');
    assert.strictEqual(config.user, undefined);
    assert.strictEqual(config.host, 'server.com');
    assert.strictEqual(config.wpPath, '/var/www/html');
    assert.strictEqual(config.wpPathEscaped, '\'/var/www/html\'');
  });

  await t.test('parses SSH URL without port', () => {
    const config = parseSshUrl('ssh://root@server.com/home/wp');
    assert.strictEqual(config.user, 'root');
    assert.strictEqual(config.host, 'server.com');
    assert.strictEqual(config.port, undefined);
    assert.strictEqual(config.wpPath, '/home/wp');
    assert.strictEqual(config.wpPathEscaped, '\'/home/wp\'');
  });

  await t.test('parses SSH URL without path', () => {
    const config = parseSshUrl('ssh://user@host');
    assert.strictEqual(config.user, 'user');
    assert.strictEqual(config.host, 'host');
    assert.strictEqual(config.wpPath, '/var/www/html');
    assert.strictEqual(config.wpPathEscaped, '\'/var/www/html\'');
  });

  await t.test('throws on invalid URL', () => {
    assert.throws(() => parseSshUrl('https://example.com'), /Invalid SSH URL/);
    assert.throws(() => parseSshUrl('invalid'), /Invalid SSH URL/);
  });
});
