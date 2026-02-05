#!/usr/bin/env node
/**
 * WpVet CLI - WordPress Security Scanner
 */

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { DEFAULT_OPTIONS, type ScanOptions } from './types.js';
import { parseWpCliInput, wpcliToDetectionResult } from './wpcli.js';
import { scanRemote } from './remote.js';
import { format } from './output.js';

const VERSION = '0.1.0';

const HELP = `
wpvet - WordPress plugin/theme security scanner with CPE output

USAGE:
  wpvet detect <url>              Scan a WordPress site remotely
  wpvet detect --stdin            Parse WP-CLI JSON from stdin

OPTIONS:
  -f, --format <fmt>    Output format: cpe, json, table (default: table)
  -t, --timeout <ms>    Request timeout in milliseconds (default: 30000)
  -v, --verbose         Verbose output
  -h, --help            Show this help
  --version             Show version

EXAMPLES:
  # Remote scan
  wpvet detect https://example.com

  # WP-CLI integration (on WordPress server)
  wp plugin list --format=json | wpvet detect --stdin --format cpe

  # Combined core + plugins + themes
  {
    echo '{"plugins":'
    wp plugin list --format=json
    echo ',"themes":'
    wp theme list --format=json
    echo '}'
  } | wpvet detect --stdin

OUTPUT:
  CPE format outputs one CPE per line for vulnerability correlation:
    cpe:2.3:a:developer:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*

  JSON format outputs full detection result for programmatic use.

  Table format (default) outputs human-readable summary.
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

  const command = positionals[0];

  if (command !== 'detect') {
    console.error(`Unknown command: ${command}`);
    console.error('Run "wpvet --help" for usage.');
    process.exit(1);
  }

  const options: ScanOptions = {
    ...DEFAULT_OPTIONS,
    format: (values.format as 'cpe' | 'json' | 'table') || 'table',
    timeout: parseInt(values.timeout || '30000', 10),
    verbose: values.verbose || false,
    stdin: values.stdin || false,
  };

  try {
    let result;

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

    console.log(format(result, options.format));

    // Exit with error if no components found
    if (!result.core && result.plugins.length === 0 && result.themes.length === 0) {
      process.exit(1);
    }
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();
