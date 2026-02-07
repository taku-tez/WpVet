/**
 * SSH module tests - v0.3.0
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parseSshUrl, shellEscape, SshErrorType } from './ssh.js';

test('parseSshUrl - basic URL', () => {
  const config = parseSshUrl('ssh://root@example.com/var/www/html');
  assert.strictEqual(config.user, 'root');
  assert.strictEqual(config.host, 'example.com');
  assert.strictEqual(config.wpPath, '/var/www/html');
  assert.strictEqual(config.port, undefined);
});

test('parseSshUrl - with port', () => {
  const config = parseSshUrl('ssh://user@example.com:2222/path');
  assert.strictEqual(config.port, 2222);
  assert.strictEqual(config.user, 'user');
  assert.strictEqual(config.host, 'example.com');
  assert.strictEqual(config.wpPath, '/path');
});

test('parseSshUrl - without user', () => {
  const config = parseSshUrl('ssh://server.local/var/www');
  assert.strictEqual(config.user, undefined);
  assert.strictEqual(config.host, 'server.local');
  assert.strictEqual(config.wpPath, '/var/www');
});

test('parseSshUrl - without path uses default', () => {
  const config = parseSshUrl('ssh://user@host');
  assert.strictEqual(config.wpPath, '/var/www/html');
});

test('parseSshUrl - with query parameters', () => {
  const config = parseSshUrl('ssh://user@host/path?wp-cli=/opt/wp-cli/wp&path=/override');
  assert.strictEqual(config.host, 'host');
  assert.strictEqual(config.wpPath, '/override');
  assert.strictEqual(config.wpCli, '/opt/wp-cli/wp');
});

test('parseSshUrl - query path overrides URL path', () => {
  const config = parseSshUrl('ssh://user@host/original?path=/new/path');
  assert.strictEqual(config.wpPath, '/new/path');
});

test('parseSshUrl - only wp-cli query', () => {
  const config = parseSshUrl('ssh://user@host/var/www?wp-cli=/usr/local/bin/wp');
  assert.strictEqual(config.wpPath, '/var/www');
  assert.strictEqual(config.wpCli, '/usr/local/bin/wp');
});

test('parseSshUrl - invalid URL throws', () => {
  assert.throws(() => parseSshUrl('not-an-ssh-url'), /Invalid SSH URL/);
});

test('parseSshUrl - invalid protocol throws', () => {
  assert.throws(() => parseSshUrl('http://example.com'), /Invalid SSH URL/);
});

test('parseSshUrl - empty path in URL', () => {
  const config = parseSshUrl('ssh://user@host/');
  assert.strictEqual(config.wpPath, '/');
});

test('parseSshUrl - complex path', () => {
  const config = parseSshUrl('ssh://deploy@prod.example.com:22/home/deploy/apps/wordpress');
  assert.strictEqual(config.user, 'deploy');
  assert.strictEqual(config.host, 'prod.example.com');
  assert.strictEqual(config.port, 22);
  assert.strictEqual(config.wpPath, '/home/deploy/apps/wordpress');
});



test('parseSshUrl - decodes escaped path query with spaces and semicolon', () => {
  const config = parseSshUrl('ssh://user@host/path?path=%2Fvar%2Fwww%2Fmy%20site%3Bprod');
  assert.strictEqual(config.wpPath, '/var/www/my site;prod');
});

test('shellEscape - escapes single quotes safely', () => {
  const escaped = shellEscape("/var/www/O'Reilly site;prod");
  assert.strictEqual(escaped, "'/var/www/O'\"'\"'Reilly site;prod'");
});

test('shellEscape - wraps whitespace and shell metacharacters safely', () => {
  const escaped = shellEscape('/var/www/my site; rm -rf /');
  assert.strictEqual(escaped, "'/var/www/my site; rm -rf /'");
});

test('SshErrorType enum values', () => {
  assert.strictEqual(SshErrorType.AUTH_FAILED, 'AUTH_FAILED');
  assert.strictEqual(SshErrorType.TIMEOUT, 'TIMEOUT');
  assert.strictEqual(SshErrorType.CONNECTION_REFUSED, 'CONNECTION_REFUSED');
  assert.strictEqual(SshErrorType.HOST_NOT_FOUND, 'HOST_NOT_FOUND');
  assert.strictEqual(SshErrorType.COMMAND_FAILED, 'COMMAND_FAILED');
  assert.strictEqual(SshErrorType.JSON_PARSE_ERROR, 'JSON_PARSE_ERROR');
  assert.strictEqual(SshErrorType.WP_CLI_NOT_FOUND, 'WP_CLI_NOT_FOUND');
  assert.strictEqual(SshErrorType.WP_NOT_FOUND, 'WP_NOT_FOUND');
  assert.strictEqual(SshErrorType.UNKNOWN, 'UNKNOWN');
});
