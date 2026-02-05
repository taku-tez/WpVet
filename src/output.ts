/**
 * Output formatting for WpVet
 */

import type { DetectionResult, DetectedComponent } from './types.js';

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
  return str.length >= len ? str : str + ' '.repeat(len - str.length);
}

export function formatTable(result: DetectionResult): string {
  const lines: string[] = [];
  
  lines.push(`Target: ${result.target}`);
  lines.push(`Scan time: ${result.timestamp}`);
  lines.push(`Source: ${result.source}`);
  lines.push('');
  
  if (result.core) {
    lines.push('WordPress Core:');
    lines.push(`  Version: ${result.core.version} (confidence: ${result.core.confidence}%)`);
    lines.push(`  CPE: ${result.core.cpe}`);
    lines.push('');
  }
  
  if (result.plugins.length > 0) {
    lines.push('Plugins:');
    lines.push(`  ${pad('Name', 30)} ${pad('Version', 12)} ${pad('Status', 10)} Confidence`);
    lines.push(`  ${'-'.repeat(30)} ${'-'.repeat(12)} ${'-'.repeat(10)} ${'-'.repeat(10)}`);
    
    for (const p of result.plugins) {
      const status = p.status || '-';
      lines.push(`  ${pad(p.name, 30)} ${pad(p.version, 12)} ${pad(status, 10)} ${p.confidence}%`);
    }
    lines.push('');
  }
  
  if (result.themes.length > 0) {
    lines.push('Themes:');
    lines.push(`  ${pad('Name', 30)} ${pad('Version', 12)} ${pad('Status', 10)} Confidence`);
    lines.push(`  ${'-'.repeat(30)} ${'-'.repeat(12)} ${'-'.repeat(10)} ${'-'.repeat(10)}`);
    
    for (const t of result.themes) {
      const status = t.status || '-';
      lines.push(`  ${pad(t.name, 30)} ${pad(t.version, 12)} ${pad(status, 10)} ${t.confidence}%`);
    }
    lines.push('');
  }
  
  if (result.errors.length > 0) {
    lines.push('Errors:');
    for (const e of result.errors) {
      lines.push(`  - ${e}`);
    }
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
