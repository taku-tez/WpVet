#!/usr/bin/env node
/**
 * WpVet CLI - WordPress Security Scanner
 */

import { parseArgs } from 'node:util';
import { DEFAULT_OPTIONS, type ScanOptions } from './types.js';
import { parseWpCliInput, wpcliToDetectionResult } from './wpcli.js';
import { scanRemote } from './remote.js';
import { parseSshUrl, scanViaSsh } from './ssh.js';
import { format } from './output.js';

const VERSION = '0.2.0';

const HELP = `
wpvet - WordPress plugin/theme security scanner with CPE output

USAGE:
  wpvet detect <url>              Scan a WordPress site remotely
  wpvet detect --stdin            Parse WP-CLI JSON from stdin
  wpvet scan <ssh-url>            Scan via SSH + WP-CLI (100% accuracy)

OPTIONS:
  -f, --format <fmt>    Output format: cpe, json, table (default: table)
  -t, --timeout <ms>    Request timeout in milliseconds (default: 30000)
  -k, --ssh-key <path>  SSH private key path
  --wp-cli <path>       WP-CLI binary path (default: wp)
  -v, --verbose         Verbose output
  -h, --help            Show this help
  --version             Show version

EXAMPLES:
  # Remote scan (60-85% accuracy)
  wpvet detect https://example.com

  # SSH + WP-CLI scan (100% accuracy)
  wpvet scan ssh://user@host/var/www/wordpress
  wpvet scan ssh://deploy@example.com/home/deploy/wp -k ~/.ssh/id_rsa

  # WP-CLI stdin integration
  wp plugin list --format=json | wpvet detect --stdin --format cpe

OUTPUT FORMATS:
  cpe     One CPE per line (for vulnerability DB correlation)
  json    Full detection result as JSON
  table   Human-readable summary (default)

SSH URL FORMAT:
  ssh://[user@]host[:port]/wordpress-path
  
  Examples:
    ssh://root@server.com/var/www/html
    ssh://deploy@example.com:2222/home/user/wordpress
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      format: { type: 'string', short: 'f', default: 'table' },
      timeout: { type: 'string', short: 't', default: '30000' },
      verbose: { type: 'boolean', short: 'v', default: false },
      stdin: { type: 'boolean', default: false },
      'ssh-key': { type: 'string', short: 'k' },
      'wp-cli': { type: 'string', default: 'wp' },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });

  if (values.version) {
    console.log(`wpvet v${VERSION}`);
    process.exit(0);
  }

  if (values.help || positionals.length === 0) {
    console.log(HELP);
    process.exit(0);
  }

  const formatValue = (values.format ?? 'table').toString();
  const validFormats = ['cpe', 'json', 'table'];
  if (!validFormats.includes(formatValue)) {
    console.error(`Error: Invalid format "${formatValue}".`);
    console.error('Run "wpvet --help" for usage.');
    console.error(HELP);
    process.exit(1);
  }

  const timeoutValue = Number(values.timeout ?? '30000');
  if (!Number.isFinite(timeoutValue) || timeoutValue <= 0) {
    console.error('Error: Invalid timeout value.');
    console.error('Run "wpvet --help" for usage.');
    console.error(HELP);
    process.exit(1);
  }

  const command = positionals[0];

  const options: ScanOptions = {
    ...DEFAULT_OPTIONS,
    format: formatValue as 'cpe' | 'json' | 'table',
    timeout: timeoutValue,
    verbose: values.verbose || false,
    stdin: values.stdin || false,
  };

  try {
    let result;

    if (command === 'detect') {
      if (options.stdin) {
        // Read from stdin (WP-CLI JSON)
        const input = await readStdin();
        const parsed = parseWpCliInput(input);
        result = wpcliToDetectionResult(parsed, 'stdin');
      } else {
        // Remote scan
        const url = positionals[1];
        if (!url) {
          console.error('Error: URL required for remote scan');
          console.error('Usage: wpvet detect <url>');
          process.exit(1);
        }
        result = await scanRemote(url, options);
      }
    } else if (command === 'scan') {
      // SSH + WP-CLI scan
      const sshUrl = positionals[1];
      if (!sshUrl) {
        console.error('Error: SSH URL required');
        console.error('Usage: wpvet scan ssh://user@host/path');
        process.exit(1);
      }
      
      const sshConfig = parseSshUrl(sshUrl);
      if (values['ssh-key']) {
        sshConfig.keyPath = values['ssh-key'];
      }
      if (values['wp-cli']) {
        sshConfig.wpCli = values['wp-cli'];
      }
      
      if (options.verbose) {
        console.error(`Connecting to ${sshConfig.host}...`);
      }
      
      result = await scanViaSsh(sshConfig, options);
    } else {
      console.error(`Unknown command: ${command}`);
      console.error('Run "wpvet --help" for usage.');
      process.exit(1);
    }

    console.log(format(result, options.format));

    // Exit with error if no components found or errors occurred
    if (result.errors.length > 0) {
      process.exit(1);
    }
    if (!result.core && result.plugins.length === 0 && result.themes.length === 0) {
      process.exit(1);
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();
