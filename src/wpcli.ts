/**
 * WP-CLI JSON input parser - v0.3.0
 * 
 * Enhanced with:
 * - NDJSON partial failure tracking
 * - Additional core fields (site_url, home_url, multisite)
 * - Better error handling
 */

import type { WpCliInput, WpPlugin, WpTheme, DetectedComponent, DetectionResult, SiteInfo } from './types.js';
import { generateCoreCpe, generatePluginCpe, generateThemeCpe } from './cpe.js';
import { loadConfig, getPluginVendor } from './config.js';

interface ParseError {
  line: number;
  content: string;
  error: string;
}

interface ParseResult {
  data: WpCliInput;
  errors: ParseError[];
}

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
    
    return {
      name: String(obj.name || obj.slug || 'unknown'),
      slug: String(obj.name || obj.slug || 'unknown'),
      version: String(obj.version || 'unknown'),
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
    
    return {
      name: String(obj.name || obj.slug || 'unknown'),
      slug: String(obj.name || obj.slug || 'unknown'),
      version: String(obj.version || 'unknown'),
      status: (obj.status as WpTheme['status']) || 'inactive',
      update: obj.update === 'available' ? 'available' : 'none',
      auto_update: obj.auto_update === 'on' ? 'on' : 'off',
      title: obj.title ? String(obj.title) : undefined,
      author: obj.author ? String(obj.author) : undefined,
    };
  });
}

/**
 * Parse combined WP-CLI output with NDJSON support
 */
export function parseWpCliInput(input: string): ParseResult {
  let parsed: unknown;
  const errors: ParseError[] = [];
  
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    // Try to parse as NDJSON (multiple JSON objects per line)
    const lines = input.trim().split('\n').filter(l => l.trim());
    if (lines.length === 0) {
      throw new Error('Empty input');
    }
    
    const results: WpCliInput = { plugins: [], themes: [] };
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      try {
        const obj = JSON.parse(line);
        if (Array.isArray(obj)) {
          // Detect if plugins or themes
          if (obj[0]?.stylesheet) {
            results.themes = parseThemeList(obj);
          } else {
            results.plugins = parsePluginList(obj);
          }
        } else if (typeof obj === 'object' && obj !== null) {
          // Single object - could be core info or combined result
          if (obj.version && typeof obj.version === 'string' && !obj.plugins) {
            results.core = {
              version: String(obj.version),
              site_url: obj.site_url as string | undefined,
              home_url: obj.home_url as string | undefined,
              multisite: obj.multisite as boolean | undefined,
            };
          }
        }
      } catch (lineError) {
        errors.push({
          line: i + 1,
          content: line.substring(0, 100) + (line.length > 100 ? '...' : ''),
          error: lineError instanceof Error ? lineError.message : String(lineError),
        });
      }
    }
    
    return { data: results, errors };
  }
  
  // Handle different input formats
  if (Array.isArray(parsed)) {
    // Assume plugins by default
    return { data: { plugins: parsePluginList(parsed), themes: [] }, errors };
  }
  
  if (typeof parsed === 'object' && parsed !== null) {
    const obj = parsed as Record<string, unknown>;
    
    const data: WpCliInput = {
      core: obj.core ? {
        version: String((obj.core as Record<string, unknown>).version || 'unknown'),
        site_url: (obj.core as Record<string, unknown>).site_url as string | undefined,
        home_url: (obj.core as Record<string, unknown>).home_url as string | undefined,
        multisite: (obj.core as Record<string, unknown>).multisite as boolean | undefined,
      } : undefined,
      plugins: obj.plugins ? parsePluginList(obj.plugins as unknown[]) : [],
      themes: obj.themes ? parseThemeList(obj.themes as unknown[]) : [],
    };
    
    return { data, errors };
  }
  
  throw new Error('Invalid WP-CLI input format');
}

/**
 * Convert WP-CLI input to detection result
 */
export function wpcliToDetectionResult(input: WpCliInput, target: string = 'stdin'): DetectionResult {
  const config = loadConfig();
  
  const result: DetectionResult = {
    target,
    timestamp: new Date().toISOString(),
    source: 'wp-cli',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  // Add site info if available
  if (input.core?.site_url || input.core?.home_url || input.core?.multisite !== undefined) {
    result.site = {
      site_url: input.core.site_url,
      home_url: input.core.home_url,
      multisite: input.core.multisite,
    };
  }
  
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
    const vendor = getPluginVendor(plugin.slug, config);
    result.plugins.push({
      type: 'plugin',
      slug: plugin.slug,
      name: plugin.title || plugin.name,
      version: plugin.version,
      status: plugin.status,
      update: plugin.update,
      auto_update: plugin.auto_update,
      cpe: generatePluginCpe(plugin.slug, plugin.version, vendor),
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
      update: theme.update,
      auto_update: theme.auto_update,
      cpe: generateThemeCpe(theme.slug, theme.version),
      confidence: 100,
      source: 'wp-cli',
    });
  }
  
  return result;
}

/**
 * Parse WP-CLI input and convert to detection result
 * Returns errors for partial NDJSON failures
 */
export function parseAndConvert(input: string, target: string = 'stdin'): DetectionResult {
  const { data, errors } = parseWpCliInput(input);
  const result = wpcliToDetectionResult(data, target);
  
  // Add parse errors
  for (const err of errors) {
    result.errors.push(`Line ${err.line}: ${err.error} (content: ${err.content})`);
  }
  
  return result;
}
