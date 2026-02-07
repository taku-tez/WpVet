/**
 * SSH-based WP-CLI execution - v0.3.0
 * 
 * Enhanced with:
 * - Automatic WP path detection
 * - Automatic WP-CLI path detection
 * - Better error messages
 * - URL query parameter support (?path=, ?wp-cli=)
 */

import { spawn } from 'node:child_process';
import type { DetectionResult, ScanOptions } from './types.js';
import { parseWpCliInput, wpcliToDetectionResult } from './wpcli.js';

export interface SshConfig {
  host: string;
  user?: string;
  port?: number;
  keyPath?: string;
  wpPath?: string;    // WordPress installation path
  wpCli?: string;     // WP-CLI binary path (default: wp)
}

/** Common WordPress installation paths to try */
const COMMON_WP_PATHS = [
  '/var/www/html',
  '/var/www/wordpress',
  '/var/www/public_html',
  '/var/www/htdocs',
  '/home/*/public_html',
  '/home/*/www',
  '/srv/www/htdocs',
  '/usr/share/nginx/html',
];

/** SSH error types */
export enum SshErrorType {
  AUTH_FAILED = 'AUTH_FAILED',
  TIMEOUT = 'TIMEOUT',
  CONNECTION_REFUSED = 'CONNECTION_REFUSED',
  HOST_NOT_FOUND = 'HOST_NOT_FOUND',
  COMMAND_FAILED = 'COMMAND_FAILED',
  JSON_PARSE_ERROR = 'JSON_PARSE_ERROR',
  WP_CLI_NOT_FOUND = 'WP_CLI_NOT_FOUND',
  WP_NOT_FOUND = 'WP_NOT_FOUND',
  UNKNOWN = 'UNKNOWN',
}

export class SshError extends Error {
  constructor(
    public type: SshErrorType,
    message: string,
    public exitCode?: number
  ) {
    super(message);
    this.name = 'SshError';
  }
}

/**
 * Escape a value for safe POSIX shell single-quoted usage.
 */
export function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function buildWpCliCommand(wpPath: string, wpCli: string, command: string): string {
  return `cd ${shellEscape(wpPath)} && ${shellEscape(wpCli)} ${command}`;
}

/**
 * Parse SSH URL with query parameters: ssh://user@host:port/path?wp-cli=/path&path=/override
 */
export function parseSshUrl(url: string): SshConfig {
  // Extract query string if present
  let queryString = '';
  let urlWithoutQuery = url;
  
  const queryIndex = url.indexOf('?');
  if (queryIndex !== -1) {
    queryString = url.substring(queryIndex + 1);
    urlWithoutQuery = url.substring(0, queryIndex);
  }
  
  const match = urlWithoutQuery.match(/^ssh:\/\/(?:([^@]+)@)?([^:\/]+)(?::(\d+))?(\/.*)?$/);
  if (!match) {
    throw new Error(`Invalid SSH URL: ${url}\nExpected format: ssh://[user@]host[:port]/path[?wp-cli=PATH&path=PATH]`);
  }
  
  const config: SshConfig = {
    user: match[1],
    host: match[2],
    port: match[3] ? parseInt(match[3], 10) : undefined,
    wpPath: match[4] || '/var/www/html',
  };
  
  // Parse query parameters
  if (queryString) {
    const params = new URLSearchParams(queryString);
    if (params.has('path')) {
      config.wpPath = params.get('path')!;
    }
    if (params.has('wp-cli')) {
      config.wpCli = params.get('wp-cli')!;
    }
  }
  
  return config;
}

/**
 * Classify SSH error from stderr/exit code
 */
function classifySshError(stderr: string, exitCode: number): SshError {
  const stderrLower = stderr.toLowerCase();
  
  if (stderrLower.includes('permission denied') || 
      stderrLower.includes('authentication failed') ||
      stderrLower.includes('publickey')) {
    return new SshError(
      SshErrorType.AUTH_FAILED,
      `SSH authentication failed. Check your credentials or SSH key.`,
      exitCode
    );
  }
  
  if (stderrLower.includes('connection timed out') ||
      stderrLower.includes('connection refused')) {
    return new SshError(
      SshErrorType.CONNECTION_REFUSED,
      `Could not connect to SSH server. Check host and port.`,
      exitCode
    );
  }
  
  if (stderrLower.includes('could not resolve hostname') ||
      stderrLower.includes('name or service not known')) {
    return new SshError(
      SshErrorType.HOST_NOT_FOUND,
      `Host not found. Check the hostname.`,
      exitCode
    );
  }
  
  if (stderrLower.includes('wp-cli') || stderrLower.includes('command not found: wp')) {
    return new SshError(
      SshErrorType.WP_CLI_NOT_FOUND,
      `WP-CLI not found on remote server. Install it or specify --wp-cli path.`,
      exitCode
    );
  }
  
  if (stderrLower.includes('this does not appear to be a wordpress install') ||
      stderrLower.includes('error: not a wordpress site')) {
    return new SshError(
      SshErrorType.WP_NOT_FOUND,
      `WordPress not found at the specified path.`,
      exitCode
    );
  }
  
  return new SshError(
    SshErrorType.COMMAND_FAILED,
    `SSH command failed (exit ${exitCode}): ${stderr || 'Unknown error'}`,
    exitCode
  );
}

/**
 * Execute command via SSH
 */
async function sshExec(
  config: SshConfig,
  command: string,
  timeout: number = 30000
): Promise<string> {
  return new Promise((resolve, reject) => {
    const args: string[] = [];
    
    // SSH options
    args.push('-o', 'BatchMode=yes');
    args.push('-o', 'StrictHostKeyChecking=accept-new');
    args.push('-o', `ConnectTimeout=${Math.floor(timeout / 1000)}`);
    
    if (config.port) {
      args.push('-p', config.port.toString());
    }
    
    if (config.keyPath) {
      args.push('-i', config.keyPath);
    }
    
    // Build destination
    const dest = config.user ? `${config.user}@${config.host}` : config.host;
    args.push(dest);
    
    // Command to execute
    args.push(command);
    
    const proc = spawn('ssh', args, {
      timeout,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => { stdout += data; });
    proc.stderr.on('data', (data) => { stderr += data; });
    
    proc.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(classifySshError(stderr || stdout, code || 1));
      }
    });
    
    proc.on('error', (err) => {
      if (err.message.includes('ETIMEDOUT') || err.message.includes('timeout')) {
        reject(new SshError(SshErrorType.TIMEOUT, `SSH connection timed out after ${timeout}ms`));
      } else {
        reject(new SshError(SshErrorType.UNKNOWN, `SSH error: ${err.message}`));
      }
    });
  });
}

/**
 * Find WP-CLI binary path
 */
async function findWpCli(
  config: SshConfig,
  timeout: number
): Promise<string> {
  const paths = ['wp', '/usr/local/bin/wp', '/usr/bin/wp'];
  
  if (config.wpCli) {
    paths.unshift(config.wpCli);
  }
  
  for (const path of paths) {
    try {
      await sshExec(config, `${shellEscape(path)} --version 2>/dev/null`, timeout);
      return path;
    } catch {
      continue;
    }
  }
  
  // Try 'which wp' as fallback
  try {
    const wpPath = (await sshExec(config, 'which wp 2>/dev/null', timeout)).trim();
    if (wpPath) return wpPath;
  } catch {
    // Ignore
  }
  
  throw new SshError(
    SshErrorType.WP_CLI_NOT_FOUND,
    'WP-CLI not found. Install it or specify --wp-cli path.'
  );
}

/**
 * Find WordPress installation path
 */
async function findWpPath(
  config: SshConfig,
  wpCli: string,
  timeout: number
): Promise<string> {
  // If path is specified, use it
  if (config.wpPath && config.wpPath !== '/var/www/html') {
    // Verify it's a valid WordPress installation
    try {
      await sshExec(config, buildWpCliCommand(config.wpPath, wpCli, 'core version 2>/dev/null'), timeout);
      return config.wpPath;
    } catch {
      // Continue to auto-detect
    }
  }
  
  // Try common paths
  for (const pathPattern of COMMON_WP_PATHS) {
    try {
      // Expand wildcards
      const expandedPaths = await sshExec(
        config,
        `ls -d ${pathPattern} 2>/dev/null || true`,
        timeout
      );
      
      for (const path of expandedPaths.trim().split('\n').filter(Boolean)) {
        try {
          await sshExec(config, buildWpCliCommand(path, wpCli, 'core version 2>/dev/null'), timeout);
          return path;
        } catch {
          continue;
        }
      }
    } catch {
      continue;
    }
  }
  
  // Default to specified path or /var/www/html
  return config.wpPath || '/var/www/html';
}

/**
 * Scan WordPress via SSH + WP-CLI
 */
export async function scanViaSsh(
  config: SshConfig,
  options: ScanOptions
): Promise<DetectionResult> {
  const result: DetectionResult = {
    target: `ssh://${config.user ? config.user + '@' : ''}${config.host}${config.wpPath || ''}`,
    timestamp: new Date().toISOString(),
    source: 'wp-cli',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  try {
    // Find WP-CLI
    const wpCli = await findWpCli(config, options.timeout);
    if (options.verbose) {
      console.error(`Using WP-CLI: ${wpCli}`);
    }
    
    // Find WordPress path
    const wpPath = await findWpPath(config, wpCli, options.timeout);
    if (options.verbose) {
      console.error(`WordPress path: ${wpPath}`);
    }
    
    // Update target with resolved path
    result.target = `ssh://${config.user ? config.user + '@' : ''}${config.host}${wpPath}`;
    
    // Get core version
    const coreVersion = (await sshExec(
      config,
      buildWpCliCommand(wpPath, wpCli, 'core version 2>/dev/null'),
      options.timeout
    )).trim();
    
    // Get site info
    let siteInfo = {};
    try {
      const siteJson = await sshExec(
        config,
        buildWpCliCommand(wpPath, wpCli, 'option get siteurl --format=json 2>/dev/null'),
        options.timeout
      );
      const homeJson = await sshExec(
        config,
        buildWpCliCommand(wpPath, wpCli, 'option get home --format=json 2>/dev/null'),
        options.timeout
      );
      const multisiteJson = await sshExec(
        config,
        buildWpCliCommand(wpPath, wpCli, 'config get MULTISITE --format=json 2>/dev/null || echo "false"'),
        options.timeout
      );
      
      siteInfo = {
        site_url: JSON.parse(siteJson),
        home_url: JSON.parse(homeJson),
        multisite: JSON.parse(multisiteJson) === true,
      };
    } catch {
      // Site info is optional
    }
    
    // Get plugins
    const pluginJson = await sshExec(
      config,
      buildWpCliCommand(wpPath, wpCli, 'plugin list --format=json 2>/dev/null'),
      options.timeout
    );
    
    // Get themes
    const themeJson = await sshExec(
      config,
      buildWpCliCommand(wpPath, wpCli, 'theme list --format=json 2>/dev/null'),
      options.timeout
    );
    
    // Parse and combine
    let plugins = [];
    let themes = [];
    
    try {
      plugins = JSON.parse(pluginJson || '[]');
    } catch (e) {
      result.errors.push(`Failed to parse plugin list: ${e}`);
    }
    
    try {
      themes = JSON.parse(themeJson || '[]');
    } catch (e) {
      result.errors.push(`Failed to parse theme list: ${e}`);
    }
    
    const combined = {
      core: { version: coreVersion, ...siteInfo },
      plugins,
      themes,
    };
    
    const parsed = wpcliToDetectionResult(combined, result.target);
    
    // Copy site info
    if (Object.keys(siteInfo).length > 0) {
      parsed.site = siteInfo;
    }
    
    return parsed;
    
  } catch (error) {
    if (error instanceof SshError) {
      result.errors.push(`[${error.type}] ${error.message}`);
    } else {
      result.errors.push(error instanceof Error ? error.message : String(error));
    }
    return result;
  }
}
