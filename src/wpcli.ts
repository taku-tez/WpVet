/**
 * WP-CLI JSON input parser
 * 
 * Parses output from:
 *   wp plugin list --format=json
 *   wp theme list --format=json
 *   wp core version
 */

import type { WpCliInput, WpPlugin, WpTheme, DetectedComponent, DetectionResult } from './types.js';
import { generateCoreCpe, generatePluginCpe, generateThemeCpe } from './cpe.js';

/**
 * Parse WP-CLI plugin list JSON
 */
export function parsePluginList(json: unknown[]): WpPlugin[] {
  if (!Array.isArray(json)) {
    throw new Error('Expected array for plugin list');
  }
  
  return json.map((item, index) => {
    if (typeof item !== 'object' || item === null) {
      throw new Error(`Invalid plugin entry at index ${index}`);
    }
    
    const obj = item as Record<string, unknown>;
    
    const version = typeof obj.version === 'string' ? obj.version.trim() : obj.version;

    return {
      name: String(obj.name || obj.slug || 'unknown'),
      slug: String(obj.name || obj.slug || 'unknown'),
      version: version ? String(version) : 'unknown',
      status: (obj.status as WpPlugin['status']) || 'inactive',
      update: obj.update === 'available' ? 'available' : 'none',
      auto_update: obj.auto_update === 'on' ? 'on' : 'off',
      title: obj.title ? String(obj.title) : undefined,
      author: obj.author ? String(obj.author) : undefined,
      description: obj.description ? String(obj.description) : undefined,
    };
  });
}

/**
 * Parse WP-CLI theme list JSON
 */
export function parseThemeList(json: unknown[]): WpTheme[] {
  if (!Array.isArray(json)) {
    throw new Error('Expected array for theme list');
  }
  
  return json.map((item, index) => {
    if (typeof item !== 'object' || item === null) {
      throw new Error(`Invalid theme entry at index ${index}`);
    }
    
    const obj = item as Record<string, unknown>;
    
    const version = typeof obj.version === 'string' ? obj.version.trim() : obj.version;

    return {
      name: String(obj.name || obj.slug || 'unknown'),
      slug: String(obj.stylesheet || obj.name || 'unknown'),
      version: version ? String(version) : 'unknown',
      status: (obj.status as WpTheme['status']) || 'inactive',
      update: obj.update === 'available' ? 'available' : 'none',
      title: obj.title ? String(obj.title) : undefined,
      author: obj.author ? String(obj.author) : undefined,
    };
  });
}

/**
 * Parse combined WP-CLI output
 * 
 * Supports:
 * - Array of plugins or themes
 * - Object with { plugins: [], themes: [], core: {} }
 */
export function parseWpCliInput(input: string): WpCliInput {
  let parsed: unknown;
  
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    // Try to parse as NDJSON (multiple JSON objects)
    const lines = input.trim().split('\n').filter(l => l.trim());
    if (lines.length === 0) {
      throw new Error('Empty input');
    }
    
    const results: WpCliInput = { plugins: [], themes: [] };
    
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (Array.isArray(obj)) {
          // Try to detect if it's plugins or themes
          if (obj[0]?.status === 'active' || obj[0]?.status === 'inactive') {
            // Could be either, check for theme-specific fields
            if (obj[0]?.stylesheet) {
              results.themes = parseThemeList(obj);
            } else {
              results.plugins = parsePluginList(obj);
            }
          }
        }
      } catch {
        // Skip invalid lines
      }
    }
    
    return results;
  }
  
  // Handle different input formats
  if (Array.isArray(parsed)) {
    // Assume plugins by default
    return { plugins: parsePluginList(parsed), themes: [] };
  }
  
  if (typeof parsed === 'object' && parsed !== null) {
    const obj = parsed as Record<string, unknown>;
    
    return {
      core: obj.core ? {
        version: String((obj.core as Record<string, unknown>).version || 'unknown'),
        site_url: (obj.core as Record<string, unknown>).site_url as string | undefined,
      } : undefined,
      plugins: obj.plugins ? parsePluginList(obj.plugins as unknown[]) : [],
      themes: obj.themes ? parseThemeList(obj.themes as unknown[]) : [],
    };
  }
  
  throw new Error('Invalid WP-CLI input format');
}

/**
 * Convert WP-CLI input to detection result
 */
export function wpcliToDetectionResult(input: WpCliInput, target: string = 'stdin'): DetectionResult {
  const result: DetectionResult = {
    target,
    timestamp: new Date().toISOString(),
    source: 'wp-cli',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  // Process core
  if (input.core) {
    result.core = {
      type: 'core',
      slug: 'wordpress',
      name: 'WordPress',
      version: input.core.version,
      cpe: generateCoreCpe(input.core.version),
      confidence: 100,
      source: 'wp-cli',
    };
  }
  
  // Process plugins
  for (const plugin of input.plugins || []) {
    result.plugins.push({
      type: 'plugin',
      slug: plugin.slug,
      name: plugin.title || plugin.name,
      version: plugin.version,
      status: plugin.status,
      cpe: generatePluginCpe(plugin.slug, plugin.version),
      confidence: 100,
      source: 'wp-cli',
    });
  }
  
  // Process themes
  for (const theme of input.themes || []) {
    result.themes.push({
      type: 'theme',
      slug: theme.slug,
      name: theme.title || theme.name,
      version: theme.version,
      status: theme.status,
      cpe: generateThemeCpe(theme.slug, theme.version),
      confidence: 100,
      source: 'wp-cli',
    });
  }
  
  return result;
}
