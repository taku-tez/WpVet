/**
 * CPE (Common Platform Enumeration) generation for WordPress components
 * 
 * Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:wordpress:*:*
 */

import type { DetectedComponent } from './types.js';

/**
 * Normalize slug for CPE vendor/product fields
 * CPE allows: alphanumeric, hyphen, period, underscore
 */
function normalizeCpeField(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\-._]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
}

/**
 * Escape special characters in CPE value
 */
function escapeCpeValue(value: string): string {
  // CPE 2.3 special chars: \ * ? "
  return value.replace(/[\\*?"]/g, '\\$&');
}

/**
 * Generate CPE 2.3 string for WordPress core
 */
export function generateCoreCpe(version: string): string {
  const escapedVersion = escapeCpeValue(version);
  return `cpe:2.3:a:wordpress:wordpress:${escapedVersion}:*:*:*:*:*:*:*`;
}

/**
 * Generate CPE 2.3 string for a WordPress plugin
 * 
 * Note: In real-world scenarios, vendor should be looked up from plugin metadata
 * or a known plugin database. This implementation uses slug as vendor for simplicity.
 */
export function generatePluginCpe(slug: string, version: string, vendor?: string): string {
  const normalizedVendor = normalizeCpeField(vendor || slug);
  const normalizedProduct = normalizeCpeField(slug);
  const escapedVersion = escapeCpeValue(version);
  
  return `cpe:2.3:a:${normalizedVendor}:${normalizedProduct}:${escapedVersion}:*:*:*:*:wordpress:*:*`;
}

/**
 * Generate CPE 2.3 string for a WordPress theme
 */
export function generateThemeCpe(slug: string, version: string, vendor?: string): string {
  const normalizedVendor = normalizeCpeField(vendor || slug);
  const normalizedProduct = normalizeCpeField(slug);
  const escapedVersion = escapeCpeValue(version);
  
  // Using target_sw=wordpress to indicate it's a WP theme
  return `cpe:2.3:a:${normalizedVendor}:${normalizedProduct}:${escapedVersion}:*:*:*:*:wordpress:*:*`;
}

/**
 * Generate CPE for any detected component
 */
export function generateCpe(component: DetectedComponent): string {
  switch (component.type) {
    case 'core':
      return generateCoreCpe(component.version);
    case 'plugin':
      return generatePluginCpe(component.slug, component.version);
    case 'theme':
      return generateThemeCpe(component.slug, component.version);
    default:
      throw new Error(`Unknown component type: ${component.type}`);
  }
}

/**
 * Parse CPE 2.3 string back to components
 */
export function parseCpe(cpe: string): {
  vendor: string;
  product: string;
  version: string;
  targetSw: string;
} | null {
  const match = cpe.match(/^cpe:2\.3:a:([^:]+):([^:]+):([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:([^:]*)/);
  if (!match) return null;
  
  return {
    vendor: match[1],
    product: match[2],
    version: match[3],
    targetSw: match[4] || '*',
  };
}
