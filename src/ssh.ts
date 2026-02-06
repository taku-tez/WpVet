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
  wpCli?: string;   // WP-CLI binary path (default: wp)
}

/**
 * Parse SSH URL: ssh://user@host:port/path
 */
export function parseSshUrl(url: string): SshConfig {
  const match = url.match(/^ssh:\/\/(?:([^@]+)@)?([^:\/]+)(?::(\d+))?(\/.*)?$/);
  if (!match) {
    throw new Error(`Invalid SSH URL: ${url}`);
  }
  
  return {
    user: match[1],
    host: match[2],
    port: match[3] ? parseInt(match[3], 10) : undefined,
    wpPath: match[4] || '/var/www/html',
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
    const coreCmd = `cd ${wpPath} && ${wpCli} core version 2>/dev/null`;
    const coreVersion = (await sshExec(config, coreCmd, options.timeout)).trim();
    
    // Get plugins
    const pluginCmd = `cd ${wpPath} && ${wpCli} plugin list --format=json 2>/dev/null`;
    const pluginJson = await sshExec(config, pluginCmd, options.timeout);
    
    // Get themes
    const themeCmd = `cd ${wpPath} && ${wpCli} theme list --format=json 2>/dev/null`;
    const themeJson = await sshExec(config, themeCmd, options.timeout);
    
    // Combine into WP-CLI format
    const combined = {
      core: { version: coreVersion },
      plugins: JSON.parse(pluginJson || '[]'),
      themes: JSON.parse(themeJson || '[]'),
    };
    
    const parsed = wpcliToDetectionResult(combined, result.target);
    return parsed;
    
  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : String(error));
    return result;
  }
}
