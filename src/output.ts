/**
 * Output formatting for WpVet - v0.3.0
 * 
 * Enhanced with:
 * - update, auto_update columns in table output
 * - Site info display
 */

import type { DetectionResult, DetectedComponent, SiteInfo } from './types.js';

export function formatCpe(result: DetectionResult): string {
  const cpes: string[] = [];
  
  if (result.core) {
    cpes.push(result.core.cpe);
  }
  
  for (const plugin of result.plugins) {
    cpes.push(plugin.cpe);
  }
  
  for (const theme of result.themes) {
    cpes.push(theme.cpe);
  }
  
  return cpes.join('\n');
}

export function formatJson(result: DetectionResult): string {
  return JSON.stringify(result, null, 2);
}

function pad(str: string, len: number): string {
  if (str.length >= len) {
    return str.substring(0, len - 1) + '…';
  }
  return str + ' '.repeat(len - str.length);
}

function formatSiteInfo(site?: SiteInfo): string[] {
  if (!site) return [];
  
  const lines: string[] = ['Site Info:'];
  if (site.site_url) lines.push(`  Site URL: ${site.site_url}`);
  if (site.home_url) lines.push(`  Home URL: ${site.home_url}`);
  if (site.multisite !== undefined) lines.push(`  Multisite: ${site.multisite ? 'Yes' : 'No'}`);
  lines.push('');
  
  return lines;
}

export function formatTable(result: DetectionResult): string {
  const lines: string[] = [];
  
  lines.push(`Target: ${result.target}`);
  lines.push(`Scan time: ${result.timestamp}`);
  lines.push(`Source: ${result.source}`);
  lines.push('');
  
  // Site info
  if (result.site) {
    lines.push(...formatSiteInfo(result.site));
  }
  
  if (result.core) {
    lines.push('WordPress Core:');
    lines.push(`  Version: ${result.core.version} (confidence: ${result.core.confidence}%)`);
    lines.push(`  CPE: ${result.core.cpe}`);
    lines.push('');
  }
  
  if (result.plugins.length > 0) {
    lines.push('Plugins:');
    
    // Determine if we have update info
    const hasUpdateInfo = result.plugins.some(p => p.update !== undefined);
    const hasAutoUpdate = result.plugins.some(p => p.auto_update !== undefined);
    
    if (hasUpdateInfo || hasAutoUpdate) {
      // Extended header with update columns
      let header = `  ${pad('Name', 28)} ${pad('Version', 10)} ${pad('Status', 10)}`;
      if (hasUpdateInfo) header += ` ${pad('Update', 8)}`;
      if (hasAutoUpdate) header += ` ${pad('AutoUpd', 8)}`;
      header += ' Conf';
      lines.push(header);
      
      let separator = `  ${'-'.repeat(28)} ${'-'.repeat(10)} ${'-'.repeat(10)}`;
      if (hasUpdateInfo) separator += ` ${'-'.repeat(8)}`;
      if (hasAutoUpdate) separator += ` ${'-'.repeat(8)}`;
      separator += ` ${'-'.repeat(4)}`;
      lines.push(separator);
      
      for (const p of result.plugins) {
        const status = p.status || '-';
        let line = `  ${pad(p.name, 28)} ${pad(p.version, 10)} ${pad(status, 10)}`;
        if (hasUpdateInfo) {
          const update = p.update === 'available' ? '⚠ Yes' : 'No';
          line += ` ${pad(update, 8)}`;
        }
        if (hasAutoUpdate) {
          const auto = p.auto_update === 'on' ? '✓ On' : 'Off';
          line += ` ${pad(auto, 8)}`;
        }
        line += ` ${p.confidence}%`;
        lines.push(line);
      }
    } else {
      // Simple header without update columns
      lines.push(`  ${pad('Name', 30)} ${pad('Version', 12)} ${pad('Status', 10)} Confidence`);
      lines.push(`  ${'-'.repeat(30)} ${'-'.repeat(12)} ${'-'.repeat(10)} ${'-'.repeat(10)}`);
      
      for (const p of result.plugins) {
        const status = p.status || '-';
        lines.push(`  ${pad(p.name, 30)} ${pad(p.version, 12)} ${pad(status, 10)} ${p.confidence}%`);
      }
    }
    lines.push('');
  }
  
  if (result.themes.length > 0) {
    lines.push('Themes:');
    
    // Determine if we have update info
    const hasUpdateInfo = result.themes.some(t => t.update !== undefined);
    const hasAutoUpdate = result.themes.some(t => t.auto_update !== undefined);
    
    if (hasUpdateInfo || hasAutoUpdate) {
      let header = `  ${pad('Name', 28)} ${pad('Version', 10)} ${pad('Status', 10)}`;
      if (hasUpdateInfo) header += ` ${pad('Update', 8)}`;
      if (hasAutoUpdate) header += ` ${pad('AutoUpd', 8)}`;
      header += ' Conf';
      lines.push(header);
      
      let separator = `  ${'-'.repeat(28)} ${'-'.repeat(10)} ${'-'.repeat(10)}`;
      if (hasUpdateInfo) separator += ` ${'-'.repeat(8)}`;
      if (hasAutoUpdate) separator += ` ${'-'.repeat(8)}`;
      separator += ` ${'-'.repeat(4)}`;
      lines.push(separator);
      
      for (const t of result.themes) {
        const status = t.status || '-';
        let line = `  ${pad(t.name, 28)} ${pad(t.version, 10)} ${pad(status, 10)}`;
        if (hasUpdateInfo) {
          const update = t.update === 'available' ? '⚠ Yes' : 'No';
          line += ` ${pad(update, 8)}`;
        }
        if (hasAutoUpdate) {
          const auto = t.auto_update === 'on' ? '✓ On' : 'Off';
          line += ` ${pad(auto, 8)}`;
        }
        line += ` ${t.confidence}%`;
        lines.push(line);
      }
    } else {
      lines.push(`  ${pad('Name', 30)} ${pad('Version', 12)} ${pad('Status', 10)} Confidence`);
      lines.push(`  ${'-'.repeat(30)} ${'-'.repeat(12)} ${'-'.repeat(10)} ${'-'.repeat(10)}`);
      
      for (const t of result.themes) {
        const status = t.status || '-';
        lines.push(`  ${pad(t.name, 30)} ${pad(t.version, 12)} ${pad(status, 10)} ${t.confidence}%`);
      }
    }
    lines.push('');
  }
  
  if (result.errors.length > 0) {
    lines.push('Errors:');
    for (const e of result.errors) {
      lines.push(`  - ${e}`);
    }
    lines.push('');
  }
  
  const totalComponents = 
    (result.core ? 1 : 0) + 
    result.plugins.length + 
    result.themes.length;
  
  lines.push(`Total: ${totalComponents} component(s) detected`);
  
  return lines.join('\n');
}

export function format(result: DetectionResult, fmt: 'cpe' | 'json' | 'table'): string {
  switch (fmt) {
    case 'cpe':
      return formatCpe(result);
    case 'json':
      return formatJson(result);
    case 'table':
    default:
      return formatTable(result);
  }
}
