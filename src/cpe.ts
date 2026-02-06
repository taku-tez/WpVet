/**
 * CPE (Common Platform Enumeration) generation for WordPress components - v0.3.0
 * 
 * Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:wordpress:*:*
 * 
 * Enhanced with:
 * - Better vendor determination
 * - Known plugin vendor mappings
 * - Improved CPE escaping
 */

import type { DetectedComponent } from './types.js';
import { KNOWN_PLUGIN_VENDORS } from './config.js';

/**
 * Normalize slug for CPE vendor/product fields
 * CPE allows: alphanumeric, hyphen, period, underscore
 */
function normalizeCpeField(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\-._]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '') || 'unknown';
}

/**
 * Escape special characters in CPE value
 * CPE 2.3 special characters that need escaping: \ * ? "
 * Also handle colons as they're field delimiters
 */
function escapeCpeValue(value: string): string {
  if (value === 'unknown' || value === '*') {
    return '*';
  }
  
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\*/g, '\\*')
    .replace(/\?/g, '\\?')
    .replace(/"/g, '\\"')
    .replace(/:/g, '\\:');
}

/**
 * Get vendor for a plugin based on known mappings
 */
export function getVendorForPlugin(slug: string): string {
  // Check known vendors
  if (KNOWN_PLUGIN_VENDORS[slug]) {
    return normalizeCpeField(KNOWN_PLUGIN_VENDORS[slug]);
  }
  
  // Extract potential vendor from slug pattern
  // e.g., "jetpack-boost" -> "jetpack" (if jetpack is known)
  const parts = slug.split('-');
  if (parts.length > 1) {
    const potentialVendor = parts[0];
    if (KNOWN_PLUGIN_VENDORS[potentialVendor]) {
      return normalizeCpeField(KNOWN_PLUGIN_VENDORS[potentialVendor]);
    }
  }
  
  // Fall back to using slug as vendor (common in NVD for WordPress plugins)
  return normalizeCpeField(slug);
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
 * @param slug - Plugin slug (directory name)
 * @param version - Plugin version
 * @param vendor - Optional vendor override
 */
export function generatePluginCpe(slug: string, version: string, vendor?: string): string {
  const normalizedVendor = vendor 
    ? normalizeCpeField(vendor) 
    : getVendorForPlugin(slug);
  const normalizedProduct = normalizeCpeField(slug);
  const escapedVersion = escapeCpeValue(version);
  
  // Using target_sw=wordpress to indicate it's a WP plugin
  return `cpe:2.3:a:${normalizedVendor}:${normalizedProduct}:${escapedVersion}:*:*:*:*:wordpress:*:*`;
}

/**
 * Generate CPE 2.3 string for a WordPress theme
 * 
 * For themes, vendor is typically the theme author/company
 * Default to using the theme slug as vendor
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
      throw new Error(`Unknown component type: ${(component as DetectedComponent).type}`);
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
  
  // Unescape values
  const unescape = (s: string) => s
    .replace(/\\:/g, ':')
    .replace(/\\"/g, '"')
    .replace(/\\\?/g, '?')
    .replace(/\\\*/g, '*')
    .replace(/\\\\/g, '\\');
  
  return {
    vendor: unescape(match[1]),
    product: unescape(match[2]),
    version: match[3] === '*' ? 'unknown' : unescape(match[3]),
    targetSw: match[4] || '*',
  };
}

/**
 * Check if a CPE matches WordPress-related software
 */
export function isWordPressCpe(cpe: string): boolean {
  const parsed = parseCpe(cpe);
  if (!parsed) return false;
  
  return (
    parsed.targetSw === 'wordpress' ||
    parsed.vendor === 'wordpress' ||
    parsed.product === 'wordpress'
  );
}
