/**
 * SSH-based WP-CLI execution
 */

import { spawn } from 'node:child_process';
import type { DetectionResult, ScanOptions } from './types.js';
import { parseWpCliInput, wpcliToDetectionResult } from './wpcli.js';

export interface SshConfig {
  host: string;
  user?: string;
  port?: number;
  keyPath?: string;
  wpPath?: string;  // WordPress installation path
  wpPathEscaped?: string;
  wpCli?: string;   // WP-CLI binary path (default: wp)
  wpCliEscaped?: string;
}

function escapeShellArg(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Parse SSH URL: ssh://user@host:port/path
 */
export function parseSshUrl(url: string): SshConfig {
  const match = url.match(/^ssh:\/\/(?:([^@]+)@)?([^:\/]+)(?::(\d+))?(\/.*)?$/);
  if (!match) {
    throw new Error(`Invalid SSH URL: ${url}`);
  }

  const wpPath = match[4] || '/var/www/html';
  return {
    user: match[1],
    host: match[2],
    port: match[3] ? parseInt(match[3], 10) : undefined,
    wpPath,
    wpPathEscaped: escapeShellArg(wpPath),
  };
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
        reject(new Error(`SSH command failed (exit ${code}): ${stderr || stdout}`));
      }
    });
    
    proc.on('error', (err) => {
      reject(new Error(`SSH error: ${err.message}`));
    });
  });
}

/**
 * Scan WordPress via SSH + WP-CLI
 */
export async function scanViaSsh(
  config: SshConfig,
  options: ScanOptions
): Promise<DetectionResult> {
  const wpCli = config.wpCli || 'wp';
  const wpPath = config.wpPath || '/var/www/html';
  const escapedWpCli = config.wpCliEscaped ?? escapeShellArg(wpCli);
  const escapedWpPath = config.wpPathEscaped ?? escapeShellArg(wpPath);
  
  const result: DetectionResult = {
    target: `ssh://${config.user ? config.user + '@' : ''}${config.host}${wpPath}`,
    timestamp: new Date().toISOString(),
    source: 'wp-cli',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  try {
    // Get core version
    const coreCmd = `cd ${escapedWpPath} && ${escapedWpCli} core version 2>/dev/null`;
    let coreVersion = (await sshExec(config, coreCmd, options.timeout)).trim();
    if (!coreVersion) {
      result.errors.push('core version missing from wp core version output');
      coreVersion = 'unknown';
    }
    
    // Get plugins
    const pluginCmd = `cd ${escapedWpPath} && ${escapedWpCli} plugin list --format=json 2>/dev/null`;
    const pluginJson = await sshExec(config, pluginCmd, options.timeout);
    
    // Get themes
    const themeCmd = `cd ${escapedWpPath} && ${escapedWpCli} theme list --format=json 2>/dev/null`;
    const themeJson = await sshExec(config, themeCmd, options.timeout);
    
    // Combine into WP-CLI format
    let plugins: unknown[] = [];
    try {
      plugins = JSON.parse(pluginJson || '[]');
    } catch (error) {
      result.errors.push(
        `plugin JSON parse failed: ${error instanceof Error ? error.message : String(error)}`
      );
      plugins = [];
    }

    let themes: unknown[] = [];
    try {
      themes = JSON.parse(themeJson || '[]');
    } catch (error) {
      result.errors.push(
        `theme JSON parse failed: ${error instanceof Error ? error.message : String(error)}`
      );
      themes = [];
    }

    const combined = {
      core: { version: coreVersion },
      plugins,
      themes,
    };
    
    const parsed = wpcliToDetectionResult(combined, result.target);
    return parsed;
    
  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : String(error));
    return result;
  }
}
