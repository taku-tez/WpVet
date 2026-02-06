#!/usr/bin/env node
/**
 * WpVet CLI - WordPress Security Scanner - v0.4.0
 * 
 * Enhanced with:
 * - New CLI options (--user-agent, --concurrency, --targets, --retry, --config)
 * - Meaningful exit codes
 * - Extended help with detection methods and exit codes
 * - JS fingerprint detection for hidden meta generator
 */

import { parseArgs } from 'node:util';
import { readFileSync, existsSync } from 'node:fs';
import { DEFAULT_OPTIONS, EXIT_SUCCESS, EXIT_NOT_DETECTED, EXIT_ERROR, type ScanOptions, type AuditResult } from './types.js';
import { parseWpCliInput, wpcliToDetectionResult, parseAndConvert } from './wpcli.js';
import { scanRemote } from './remote.js';
import { parseSshUrl, scanViaSsh } from './ssh.js';
import { format, formatAudit } from './output.js';
import { initConfig } from './config.js';
import { runMisconfigChecks, runAudit } from './misconfig.js';
import { runAllPluginVulnChecks, runPluginVulnChecks } from './plugin-vulns.js';

const VERSION = '0.4.0';

const HELP = `
wpvet v${VERSION} - WordPress plugin/theme security scanner with CPE output

USAGE:
  wpvet detect <url>              Scan a WordPress site remotely
  wpvet detect --stdin            Parse WP-CLI JSON from stdin
  wpvet detect <url> --audit      Scan + security audit
  wpvet audit <url>               Security audit only (misconfigs, plugin vulns)
  wpvet scan <ssh-url>            Scan via SSH + WP-CLI (100% accuracy)
  wpvet init                      Initialize config file (~/.wpvet/config.json)

OPTIONS:
  -f, --format <fmt>       Output format: cpe, json, table (default: table)
  -t, --timeout <ms>       Request timeout in milliseconds (default: 30000)
  -k, --ssh-key <path>     SSH private key path
  --wp-cli <path>          WP-CLI binary path (default: wp)
  --user-agent <ua>        Custom User-Agent string
  --concurrency <n>        Max concurrent requests (default: 5)
  --retry <n>              Retry count for failed requests (default: 2)
  --targets <file>         File with target URLs (one per line)
  --config <path>          Path to config file (default: ~/.wpvet/config.json)
  --fingerprint            Enable JS fingerprint detection (default: on)
  --no-fingerprint         Disable JS fingerprint detection (faster scans)
  --audit                  Include security audit (misconfigs, plugin vulns)
  -v, --verbose            Verbose output
  -h, --help               Show this help
  --version                Show version

EXAMPLES:
  # Remote scan (60-85% accuracy)
  wpvet detect https://example.com

  # Remote scan with custom options
  wpvet detect https://example.com --concurrency 10 --timeout 60000

  # Batch scan from file
  wpvet detect --targets urls.txt --format cpe

  # SSH + WP-CLI scan (100% accuracy)
  wpvet scan ssh://user@host/var/www/wordpress
  wpvet scan ssh://deploy@example.com/home/deploy/wp -k ~/.ssh/id_rsa

  # SSH with query parameters
  wpvet scan "ssh://user@host/var/www?wp-cli=/usr/local/bin/wp"

  # WP-CLI stdin integration
  wp plugin list --format=json | wpvet detect --stdin --format cpe

  # Security audit (check for misconfigurations)
  wpvet audit https://example.com

  # Combined detection + audit
  wpvet detect https://example.com --audit

  # Audit with JSON output
  wpvet audit https://example.com --format json

OUTPUT FORMATS:
  cpe     One CPE per line (for vulnerability DB correlation)
  json    Full detection result as JSON
  table   Human-readable summary (default)

DETECTION METHODS:
  Remote (wpvet detect):
    - Meta generator tag extraction (confidence: 95%)
    - WordPress REST API /wp-json/ probe (confidence: 70%)
    - readme.html version parsing (confidence: 85%)
    - Script/style ?ver= parameter extraction (confidence: 80%)
    - JS fingerprint detection (confidence: 75%) [NEW in v0.4.0]
      * SHA-256 hash matching of wp-includes/js/* files
      * Version comment extraction from JS headers
    - /wp-content/plugins/<slug>/readme.txt probing
    - /wp-content/plugins/<slug>/*.js version extraction
    - /wp-content/themes/<slug>/style.css probing
    - HTML parsing for plugin/theme path discovery

  SSH (wpvet scan):
    - Direct WP-CLI execution (confidence: 100%)
    - Automatic WP-CLI path detection
    - Automatic WordPress path detection
    - Full plugin/theme list with update status

SSH URL FORMAT:
  ssh://[user@]host[:port]/wordpress-path[?options]
  
  Options:
    path=PATH       Override WordPress installation path
    wp-cli=PATH     Override WP-CLI binary path
  
  Examples:
    ssh://root@server.com/var/www/html
    ssh://deploy@example.com:2222/home/user/wordpress
    ssh://user@host/var/www?wp-cli=/opt/wp-cli/wp

CONFIG FILE (~/.wpvet/config.json):
  {
    "additionalPlugins": ["my-custom-plugin"],
    "additionalThemes": ["my-custom-theme"],
    "pluginVendors": {
      "my-plugin": "mycompany"
    },
    "timeout": 60000,
    "concurrency": 10
  }

EXIT CODES:
  0    Success - WordPress detected with components
  1    No detection - WordPress not found or no components detected
  2    Error - Connection error, timeout, or invalid input

CPE FORMAT:
  WordPress core:  cpe:2.3:a:wordpress:wordpress:VERSION:*:*:*:*:*:*:*
  Plugins/Themes:  cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:wordpress:*:*

For vulnerability correlation, pipe CPE output to your CVE database:
  wpvet detect https://example.com -f cpe | grep -f - cve-database.txt
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function readTargetsFile(path: string): Promise<string[]> {
  if (!existsSync(path)) {
    throw new Error(`Targets file not found: ${path}`);
  }
  
  const content = readFileSync(path, 'utf8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
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
      'user-agent': { type: 'string' },
      concurrency: { type: 'string', default: '5' },
      retry: { type: 'string', default: '2' },
      targets: { type: 'string' },
      config: { type: 'string' },
      fingerprint: { type: 'boolean', default: true },
      'no-fingerprint': { type: 'boolean', default: false },
      audit: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });

  if (values.version) {
    console.log(`wpvet v${VERSION}`);
    process.exit(EXIT_SUCCESS);
  }

  if (values.help || positionals.length === 0) {
    console.log(HELP);
    process.exit(EXIT_SUCCESS);
  }

  const command = positionals[0];

  // Handle init command
  if (command === 'init') {
    try {
      initConfig();
      console.log('Config file initialized at ~/.wpvet/config.json');
      process.exit(EXIT_SUCCESS);
    } catch (e) {
      console.error('Error initializing config:', e instanceof Error ? e.message : e);
      process.exit(EXIT_ERROR);
    }
  }

  const options: ScanOptions = {
    ...DEFAULT_OPTIONS,
    format: (values.format as 'cpe' | 'json' | 'table') || 'table',
    timeout: parseInt(values.timeout || '30000', 10),
    verbose: values.verbose || false,
    stdin: values.stdin || false,
    userAgent: values['user-agent'] || DEFAULT_OPTIONS.userAgent,
    concurrency: parseInt(values.concurrency || '5', 10),
    retry: parseInt(values.retry || '2', 10),
    configPath: values.config,
    fingerprint: values['no-fingerprint'] ? false : (values.fingerprint ?? true),
  };

  try {
    let results: { output: string; hasComponents: boolean; hasErrors: boolean }[] = [];

    if (command === 'detect') {
      if (options.stdin) {
        // Read from stdin (WP-CLI JSON)
        const input = await readStdin();
        const result = parseAndConvert(input, 'stdin');
        const hasComponents = !!(result.core || result.plugins.length > 0 || result.themes.length > 0);
        results.push({
          output: format(result, options.format),
          hasComponents,
          hasErrors: result.errors.length > 0,
        });
      } else if (values.targets) {
        // Batch scan from file
        const urls = await readTargetsFile(values.targets);
        if (urls.length === 0) {
          console.error('Error: No valid URLs in targets file');
          process.exit(EXIT_ERROR);
        }
        
        for (const url of urls) {
          if (options.verbose) {
            console.error(`Scanning: ${url}`);
          }
          
          const result = await scanRemote(url, options);
          
          // Run audit if --audit flag is set
          if (values.audit) {
            if (options.verbose) {
              console.error(`Running security audit on ${url}...`);
            }
            const misconfigs = await runMisconfigChecks(url, options);
            const pluginVulns = await runPluginVulnChecks(url, result.plugins, options);
            result.misconfigs = [...misconfigs, ...pluginVulns];
          }
          
          const hasComponents = !!(result.core || result.plugins.length > 0 || result.themes.length > 0);
          results.push({
            output: format(result, options.format),
            hasComponents,
            hasErrors: result.errors.length > 0,
          });
        }
      } else {
        // Single URL scan
        const url = positionals[1];
        if (!url) {
          console.error('Error: URL required for remote scan');
          console.error('Usage: wpvet detect <url>');
          process.exit(EXIT_ERROR);
        }
        
        const result = await scanRemote(url, options);
        
        // Run audit if --audit flag is set
        if (values.audit) {
          if (options.verbose) {
            console.error('Running security audit...');
          }
          const misconfigs = await runMisconfigChecks(url, options);
          const pluginVulns = await runPluginVulnChecks(url, result.plugins, options);
          result.misconfigs = [...misconfigs, ...pluginVulns];
        }
        
        const hasComponents = !!(result.core || result.plugins.length > 0 || result.themes.length > 0);
        results.push({
          output: format(result, options.format),
          hasComponents,
          hasErrors: result.errors.length > 0,
        });
      }
    } else if (command === 'audit') {
      // Security audit command
      const url = positionals[1];
      if (!url) {
        console.error('Error: URL required for security audit');
        console.error('Usage: wpvet audit <url>');
        process.exit(EXIT_ERROR);
      }
      
      if (options.verbose) {
        console.error(`Running security audit on ${url}...`);
      }
      
      const auditResult: AuditResult = {
        target: url,
        timestamp: new Date().toISOString(),
        misconfigs: [],
        pluginVulns: [],
        errors: [],
      };
      
      try {
        // Run misconfiguration checks
        auditResult.misconfigs = await runMisconfigChecks(url, options);
        
        // Run all plugin vulnerability checks (comprehensive mode)
        auditResult.pluginVulns = await runAllPluginVulnChecks(url, options);
      } catch (e) {
        auditResult.errors.push(`Audit failed: ${e instanceof Error ? e.message : e}`);
      }
      
      const hasIssues = auditResult.misconfigs.length > 0 || auditResult.pluginVulns.length > 0;
      const auditFormat = options.format === 'cpe' ? 'table' : options.format as 'json' | 'table';
      
      results.push({
        output: formatAudit(auditResult, auditFormat),
        hasComponents: hasIssues,
        hasErrors: auditResult.errors.length > 0,
      });
    } else if (command === 'scan') {
      // SSH + WP-CLI scan
      const sshUrl = positionals[1];
      if (!sshUrl) {
        console.error('Error: SSH URL required');
        console.error('Usage: wpvet scan ssh://user@host/path');
        process.exit(EXIT_ERROR);
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
      
      const result = await scanViaSsh(sshConfig, options);
      const hasComponents = !!(result.core || result.plugins.length > 0 || result.themes.length > 0);
      results.push({
        output: format(result, options.format),
        hasComponents,
        hasErrors: result.errors.length > 0,
      });
    } else {
      console.error(`Unknown command: ${command}`);
      console.error('Run "wpvet --help" for usage.');
      process.exit(EXIT_ERROR);
    }

    // Output results
    for (const r of results) {
      console.log(r.output);
      if (results.length > 1) {
        console.log(''); // Separator between results
      }
    }

    // Determine exit code
    const anyComponents = results.some(r => r.hasComponents);
    const anyErrors = results.some(r => r.hasErrors);
    
    if (anyErrors && !anyComponents) {
      process.exit(EXIT_ERROR);
    } else if (!anyComponents) {
      process.exit(EXIT_NOT_DETECTED);
    } else {
      process.exit(EXIT_SUCCESS);
    }

  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
    process.exit(EXIT_ERROR);
  }
}

main();
