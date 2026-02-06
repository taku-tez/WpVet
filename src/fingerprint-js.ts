/**
 * WordPress JS Fingerprint Detection
 * 
 * Detects WordPress version by analyzing JS file hashes and version comments
 * when meta generator tag is hidden.
 */

import { createHash } from 'crypto';
import type { ScanOptions } from './types.js';
import {
  CORE_JS_PATHS,
  WP_CORE_FINGERPRINTS,
  PLUGIN_JS_PATTERNS,
  buildHashLookup,
  type JsFingerprint,
  type PluginJsPattern,
} from './fingerprints-data.js';

/**
 * Result of JS fingerprint detection
 */
export interface JsFingerprintResult {
  version: string | null;
  confidence: number;
  source: string;
  matches: FingerprintMatch[];
}

export interface FingerprintMatch {
  path: string;
  hash: string;
  matchedVersions: string[];
}

export interface PluginVersionResult {
  plugin: string;
  version: string;
  source: string;
  confidence: number;
}

/**
 * Calculate SHA-256 hash of content
 */
export function calculateHash(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Normalize JS content for hashing
 * - Removes BOM
 * - Normalizes line endings
 * - Trims whitespace
 */
export function normalizeJsContent(content: string): string {
  return content
    .replace(/^\uFEFF/, '')           // Remove BOM
    .replace(/\r\n/g, '\n')           // Normalize CRLF to LF
    .replace(/\r/g, '\n')             // Normalize CR to LF
    .trim();
}

/**
 * Fetch JS file content
 */
async function fetchJsFile(
  url: string,
  options: ScanOptions
): Promise<string | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': options.userAgent },
      redirect: 'follow',
    });
    
    if (!response.ok) {
      return null;
    }
    
    const contentType = response.headers.get('content-type') || '';
    // Accept JS files and generic application/octet-stream
    if (!contentType.includes('javascript') && 
        !contentType.includes('text/') && 
        !contentType.includes('application/octet-stream')) {
      // Some servers return wrong content-type, still try to read
    }
    
    return await response.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Detect WordPress core version from JS fingerprints
 */
export async function detectCoreByJsFingerprint(
  baseUrl: string,
  options: ScanOptions
): Promise<JsFingerprintResult> {
  const hashLookup = buildHashLookup();
  const matches: FingerprintMatch[] = [];
  const versionCounts = new Map<string, number>();
  
  // Fetch and hash each known JS path
  for (const path of CORE_JS_PATHS) {
    const url = `${baseUrl}${path}`;
    const content = await fetchJsFile(url, options);
    
    if (!content) continue;
    
    const normalized = normalizeJsContent(content);
    const hash = calculateHash(normalized);
    
    const lookup = hashLookup.get(hash);
    if (lookup) {
      matches.push({
        path,
        hash,
        matchedVersions: lookup.versions,
      });
      
      // Count version occurrences
      for (const version of lookup.versions) {
        versionCounts.set(version, (versionCounts.get(version) || 0) + 1);
      }
    }
    
    // Also try to extract version from JS comments
    const versionFromComment = extractVersionFromJsComment(normalized);
    if (versionFromComment) {
      matches.push({
        path,
        hash,
        matchedVersions: [versionFromComment],
      });
      versionCounts.set(versionFromComment, (versionCounts.get(versionFromComment) || 0) + 2);
    }
  }
  
  if (matches.length === 0) {
    return {
      version: null,
      confidence: 0,
      source: 'js-fingerprint',
      matches: [],
    };
  }
  
  // Find version with highest count / most specific match
  let bestVersion: string | null = null;
  let maxCount = 0;
  let minVersionsMatched = Infinity;
  
  for (const [version, count] of versionCounts) {
    // Prefer versions that match more files
    // And prefer more specific matches (fewer versions sharing the hash)
    const avgVersionsPerMatch = matches
      .filter(m => m.matchedVersions.includes(version))
      .reduce((sum, m) => sum + m.matchedVersions.length, 0) / matches.length;
    
    if (count > maxCount || (count === maxCount && avgVersionsPerMatch < minVersionsMatched)) {
      maxCount = count;
      bestVersion = version;
      minVersionsMatched = avgVersionsPerMatch;
    }
  }
  
  // Calculate confidence based on number of matches and specificity
  let confidence = 50; // Base confidence for fingerprint detection
  confidence += Math.min(matches.length * 10, 25); // Up to 25 for multiple matches
  if (minVersionsMatched <= 3) confidence += 10; // Bonus for specific matches
  
  return {
    version: bestVersion,
    confidence: Math.min(confidence, 75), // Cap at 75 (fingerprint is less reliable than meta generator)
    source: 'js-fingerprint',
    matches,
  };
}

/**
 * Extract version from JS file comments
 * Looks for patterns like @version X.X.X or WordPress vX.X.X
 */
function extractVersionFromJsComment(content: string): string | null {
  // Only check first 2KB (version comments are usually at the top)
  const header = content.slice(0, 2048);
  
  const patterns = [
    /@version\s+([\d.]+)/i,
    /WordPress\s+v?([\d.]+)/i,
    /wp-version['":\s]+([\d.]+)/i,
  ];
  
  for (const pattern of patterns) {
    const match = header.match(pattern);
    if (match?.[1]) {
      // Validate it looks like a WP version (X.X or X.X.X)
      if (/^\d+\.\d+(\.\d+)?$/.test(match[1])) {
        return match[1];
      }
    }
  }
  
  return null;
}

/**
 * Detect plugin version from JS files
 */
export async function detectPluginFromJs(
  baseUrl: string,
  pluginSlug: string,
  options: ScanOptions
): Promise<PluginVersionResult | null> {
  const pattern = PLUGIN_JS_PATTERNS.find(p => p.plugin === pluginSlug);
  
  if (!pattern) {
    // For unknown plugins, try common paths
    return detectUnknownPluginFromJs(baseUrl, pluginSlug, options);
  }
  
  for (const path of pattern.paths) {
    const url = `${baseUrl}${path}`;
    const content = await fetchJsFile(url, options);
    
    if (!content) continue;
    
    // Try each version pattern
    for (const regex of pattern.versionPatterns) {
      const match = content.match(regex);
      if (match?.[1]) {
        return {
          plugin: pluginSlug,
          version: match[1],
          source: `js:${path}`,
          confidence: 80,
        };
      }
    }
    
    // If we found the file but no version, still return detection
    return {
      plugin: pluginSlug,
      version: 'detected',
      source: `js:${path}`,
      confidence: 50,
    };
  }
  
  return null;
}

/**
 * Detect version for plugins without predefined patterns
 */
async function detectUnknownPluginFromJs(
  baseUrl: string,
  pluginSlug: string,
  options: ScanOptions
): Promise<PluginVersionResult | null> {
  // Common JS paths for plugins
  const commonPaths = [
    `/wp-content/plugins/${pluginSlug}/assets/js/${pluginSlug}.min.js`,
    `/wp-content/plugins/${pluginSlug}/assets/js/${pluginSlug}.js`,
    `/wp-content/plugins/${pluginSlug}/js/${pluginSlug}.min.js`,
    `/wp-content/plugins/${pluginSlug}/js/${pluginSlug}.js`,
    `/wp-content/plugins/${pluginSlug}/public/js/${pluginSlug}-public.min.js`,
  ];
  
  const genericVersionPatterns = [
    /\/\*![^*]*v([\d.]+)/,
    /@version\s+([\d.]+)/i,
    /version['":\s]+([\d.]+)/i,
  ];
  
  for (const path of commonPaths) {
    const url = `${baseUrl}${path}`;
    const content = await fetchJsFile(url, options);
    
    if (!content) continue;
    
    const header = content.slice(0, 2048);
    
    for (const pattern of genericVersionPatterns) {
      const match = header.match(pattern);
      if (match?.[1] && /^\d+\.\d+(\.\d+)?$/.test(match[1])) {
        return {
          plugin: pluginSlug,
          version: match[1],
          source: `js:${path}`,
          confidence: 70,
        };
      }
    }
  }
  
  return null;
}

/**
 * Detect all known plugins from HTML by their JS paths
 */
export function detectPluginsFromJsPaths(html: string): Set<string> {
  const plugins = new Set<string>();
  
  for (const pattern of PLUGIN_JS_PATTERNS) {
    for (const path of pattern.paths) {
      if (html.includes(path)) {
        plugins.add(pattern.plugin);
        break;
      }
    }
  }
  
  return plugins;
}

/**
 * Extract versions from ?ver= parameters for plugins
 * Returns map of plugin slug -> potential version
 */
export function extractPluginVersionsFromVerParam(html: string): Map<string, string> {
  const versions = new Map<string, string>();
  
  // Match /wp-content/plugins/SLUG/...?ver=X.X.X
  const regex = /\/wp-content\/plugins\/([a-z0-9_-]+)\/[^"']+\?ver=([\d.]+)/gi;
  
  let match;
  while ((match = regex.exec(html)) !== null) {
    const slug = match[1].toLowerCase();
    const version = match[2];
    
    // Keep the most specific (longest) version string
    const existing = versions.get(slug);
    if (!existing || version.length > existing.length) {
      versions.set(slug, version);
    }
  }
  
  return versions;
}
