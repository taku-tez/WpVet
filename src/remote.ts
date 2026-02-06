/**
 * Remote WordPress detection - v0.4.0
 * 
 * Enhanced with:
 * - Multiple version extraction patterns (wp-json, readme.html, ?ver=)
 * - HTML parsing for plugin/theme discovery
 * - Concurrency limiting and retry with exponential backoff
 * - HTTP/HTTPS fallback
 * - JS fingerprint detection for hidden meta generator
 */

import type { DetectedComponent, DetectionResult, ScanOptions } from './types.js';
import { generateCoreCpe, generatePluginCpe, generateThemeCpe } from './cpe.js';
import { loadConfig, getPluginsToScan, getThemesToScan, getPluginVendor, type WpVetConfig } from './config.js';
import {
  detectCoreByJsFingerprint,
  detectPluginFromJs,
  extractPluginVersionsFromVerParam,
  type JsFingerprintResult,
} from './fingerprint-js.js';

/**
 * Concurrency limiter for parallel requests
 */
class ConcurrencyLimiter {
  private running = 0;
  private queue: (() => void)[] = [];
  
  constructor(private maxConcurrency: number) {}
  
  async run<T>(fn: () => Promise<T>): Promise<T> {
    while (this.running >= this.maxConcurrency) {
      await new Promise<void>(resolve => this.queue.push(resolve));
    }
    
    this.running++;
    try {
      return await fn();
    } finally {
      this.running--;
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

/**
 * Fetch with timeout, retry, and error handling
 */
async function fetchWithRetry(
  url: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<Response | null> {
  return limiter.run(async () => {
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= options.retry; attempt++) {
      if (attempt > 0) {
        // Exponential backoff
        const delay = options.retryDelay * Math.pow(2, attempt - 1);
        await new Promise(r => setTimeout(r, delay));
      }
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), options.timeout);
      
      try {
        const response = await fetch(url, {
          signal: controller.signal,
          headers: { 'User-Agent': options.userAgent },
          redirect: 'follow',
        });
        
        // Retry on 429 (rate limit) or 5xx errors
        if (response.status === 429 || response.status >= 500) {
          lastError = new Error(`HTTP ${response.status}`);
          continue;
        }
        
        return response;
      } catch (e) {
        lastError = e instanceof Error ? e : new Error(String(e));
      } finally {
        clearTimeout(timeoutId);
      }
    }
    
    return null;
  });
}

function extractVersion(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) return match[1];
  }
  return null;
}

/**
 * Extract WordPress version from multiple sources
 */
interface VersionSource {
  version: string;
  confidence: number;
  source: string;
}

async function extractCoreVersionFromHtml(
  html: string,
  baseUrl: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<VersionSource | null> {
  // 1. Meta generator tag (highest confidence)
  const generatorMatch = html.match(
    /<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)?["']/i
  );
  if (generatorMatch?.[1]) {
    return { version: generatorMatch[1], confidence: 95, source: 'meta-generator' };
  }
  
  // 2. Extract version from ?ver= in script/style tags
  const verMatches = html.matchAll(/wp-(?:includes|content)\/[^"']+\?ver=([\d.]+)/g);
  const versions = new Map<string, number>();
  for (const match of verMatches) {
    const v = match[1];
    versions.set(v, (versions.get(v) || 0) + 1);
  }
  
  if (versions.size > 0) {
    // Most common version is likely the core version
    let maxCount = 0;
    let mostCommon = '';
    for (const [v, count] of versions) {
      if (count > maxCount) {
        maxCount = count;
        mostCommon = v;
      }
    }
    if (mostCommon) {
      return { version: mostCommon, confidence: 80, source: 'ver-param' };
    }
  }
  
  return null;
}

async function extractCoreVersionFromWpJson(
  baseUrl: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<VersionSource | null> {
  // Try wp-json/wp/v2/
  const wpJsonUrl = `${baseUrl}/wp-json/`;
  const response = await fetchWithRetry(wpJsonUrl, options, limiter);
  
  if (response?.ok) {
    try {
      const json = await response.json();
      // WordPress REST API returns version in 'version' or 'gmt_offset' adjacent fields
      // The home and url fields confirm it's WordPress
      if (json.home || json.url || json.namespaces?.includes('wp/v2')) {
        // Version is not directly exposed in wp-json, but presence confirms WP
        return { version: 'detected', confidence: 70, source: 'wp-json' };
      }
    } catch {
      // Not valid JSON
    }
  }
  
  return null;
}

async function extractCoreVersionFromReadme(
  baseUrl: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<VersionSource | null> {
  const readmeUrl = `${baseUrl}/readme.html`;
  const response = await fetchWithRetry(readmeUrl, options, limiter);
  
  if (response?.ok) {
    const text = await response.text();
    // readme.html contains "Version X.X.X"
    const versionMatch = text.match(/Version\s+([\d.]+)/i);
    if (versionMatch?.[1]) {
      return { version: versionMatch[1], confidence: 85, source: 'readme.html' };
    }
    
    // Check if it's WordPress readme
    if (text.includes('WordPress') && text.includes('GPL')) {
      return { version: 'detected', confidence: 60, source: 'readme.html' };
    }
  }
  
  return null;
}

/**
 * Extract plugin slugs from HTML
 */
function extractPluginsFromHtml(html: string): Set<string> {
  const plugins = new Set<string>();
  
  // Match /wp-content/plugins/SLUG/ patterns
  const pluginPattern = /\/wp-content\/plugins\/([a-z0-9_-]+)\//gi;
  let match;
  
  while ((match = pluginPattern.exec(html)) !== null) {
    const slug = match[1].toLowerCase();
    // Filter out common non-plugin paths
    if (slug && slug !== 'plugin' && slug !== 'plugins') {
      plugins.add(slug);
    }
  }
  
  return plugins;
}

/**
 * Extract theme slugs from HTML
 */
function extractThemesFromHtml(html: string): Set<string> {
  const themes = new Set<string>();
  
  // Match /wp-content/themes/SLUG/ patterns
  const themePattern = /\/wp-content\/themes\/([a-z0-9_-]+)\//gi;
  let match;
  
  while ((match = themePattern.exec(html)) !== null) {
    const slug = match[1].toLowerCase();
    // Filter out common non-theme paths
    if (slug && slug !== 'theme' && slug !== 'themes') {
      themes.add(slug);
    }
  }
  
  return themes;
}

/**
 * Try both HTTP and HTTPS for a URL
 */
async function findActiveBaseUrl(
  url: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<{ baseUrl: string; html: string } | null> {
  const urls = [];
  
  if (url.startsWith('https://')) {
    urls.push(url, url.replace('https://', 'http://'));
  } else if (url.startsWith('http://')) {
    urls.push(url, url.replace('http://', 'https://'));
  } else {
    urls.push(`https://${url}`, `http://${url}`);
  }
  
  for (const testUrl of urls) {
    const baseUrl = testUrl.replace(/\/$/, '');
    const response = await fetchWithRetry(baseUrl, options, limiter);
    
    if (response?.ok) {
      const html = await response.text();
      // Check if this looks like WordPress
      if (html.includes('/wp-content/') || html.includes('/wp-includes/') || 
          html.includes('WordPress') || html.includes('wp-json')) {
        return { baseUrl, html };
      }
    }
  }
  
  return null;
}

export async function detectWordPressCore(
  baseUrl: string,
  html: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<DetectedComponent | null> {
  const sources: VersionSource[] = [];
  
  // Try multiple version extraction methods
  // 1. Meta generator (highest confidence)
  const htmlVersion = await extractCoreVersionFromHtml(html, baseUrl, options, limiter);
  if (htmlVersion) sources.push(htmlVersion);
  
  // 2. readme.html
  const readmeVersion = await extractCoreVersionFromReadme(baseUrl, options, limiter);
  if (readmeVersion) sources.push(readmeVersion);
  
  // 3. wp-json
  const wpJsonVersion = await extractCoreVersionFromWpJson(baseUrl, options, limiter);
  if (wpJsonVersion) sources.push(wpJsonVersion);
  
  // 4. JS fingerprint detection (when enabled and no precise version yet)
  const hasPreciseVersion = sources.some(s => 
    s.version !== 'detected' && s.version !== 'unknown'
  );
  
  if (options.fingerprint && !hasPreciseVersion) {
    try {
      const fingerprintResult = await detectCoreByJsFingerprint(baseUrl, options);
      if (fingerprintResult.version) {
        sources.push({
          version: fingerprintResult.version,
          confidence: fingerprintResult.confidence,
          source: fingerprintResult.source,
        });
      }
    } catch {
      // Fingerprint detection failed, continue with other methods
    }
  }
  
  // 5. Check if HTML has WordPress indicators (lowest confidence)
  if (sources.length === 0) {
    if (html.includes('/wp-includes/') || html.includes('/wp-content/')) {
      sources.push({ version: 'unknown', confidence: 50, source: 'wp-paths' });
    }
  }
  
  if (sources.length === 0) {
    return null;
  }
  
  // Use highest confidence source, preferring actual version over 'detected'/'unknown'
  sources.sort((a, b) => {
    // Prefer actual versions
    const aHasVersion = a.version !== 'detected' && a.version !== 'unknown';
    const bHasVersion = b.version !== 'detected' && b.version !== 'unknown';
    if (aHasVersion !== bHasVersion) return bHasVersion ? 1 : -1;
    return b.confidence - a.confidence;
  });
  
  const best = sources[0];
  const version = best.version === 'detected' ? 'unknown' : best.version;
  
  return {
    type: 'core',
    slug: 'wordpress',
    name: 'WordPress',
    version,
    cpe: generateCoreCpe(version),
    confidence: best.confidence,
    source: 'remote',
  };
}

export async function detectPlugin(
  baseUrl: string,
  slug: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter,
  config: WpVetConfig,
  verParamVersions?: Map<string, string>
): Promise<DetectedComponent | null> {
  // 1. Try readme.txt first (most reliable)
  const readmeUrl = `${baseUrl}/wp-content/plugins/${slug}/readme.txt`;
  const response = await fetchWithRetry(readmeUrl, options, limiter);
  
  if (response?.ok) {
    const text = await response.text();
    const version = extractVersion(text, [
      /Stable tag:\s*([\d.]+)/i,
      /Version:\s*([\d.]+)/i,
    ]);
    
    if (version) {
      const vendor = getPluginVendor(slug, config);
      return {
        type: 'plugin',
        slug,
        name: slug,
        version,
        cpe: generatePluginCpe(slug, version, vendor),
        confidence: 85,
        source: 'remote',
      };
    }
  }
  
  // 2. Try JS fingerprint detection
  if (options.fingerprint) {
    try {
      const jsResult = await detectPluginFromJs(baseUrl, slug, options);
      if (jsResult && jsResult.version !== 'detected') {
        const vendor = getPluginVendor(slug, config);
        return {
          type: 'plugin',
          slug,
          name: slug,
          version: jsResult.version,
          cpe: generatePluginCpe(slug, jsResult.version, vendor),
          confidence: jsResult.confidence,
          source: 'remote',
        };
      }
    } catch {
      // Continue to next method
    }
  }
  
  // 3. Try ?ver= parameter version (from HTML parsing)
  if (verParamVersions?.has(slug)) {
    const version = verParamVersions.get(slug)!;
    const vendor = getPluginVendor(slug, config);
    return {
      type: 'plugin',
      slug,
      name: slug,
      version,
      cpe: generatePluginCpe(slug, version, vendor),
      confidence: 70, // Lower confidence - ver param might be different from actual version
      source: 'remote',
    };
  }
  
  return null;
}

export async function detectTheme(
  baseUrl: string,
  slug: string,
  options: ScanOptions,
  limiter: ConcurrencyLimiter
): Promise<DetectedComponent | null> {
  const styleUrl = `${baseUrl}/wp-content/themes/${slug}/style.css`;
  const response = await fetchWithRetry(styleUrl, options, limiter);
  
  if (!response?.ok) return null;
  
  const text = await response.text();
  const version = extractVersion(text, [
    /Version:\s*([\d.]+)/i,
  ]);
  
  // Also extract theme name from style.css
  const nameMatch = text.match(/Theme Name:\s*(.+)/i);
  const name = nameMatch?.[1]?.trim() || slug;
  
  if (version) {
    return {
      type: 'theme',
      slug,
      name,
      version,
      cpe: generateThemeCpe(slug, version),
      confidence: 85,
      source: 'remote',
    };
  }
  
  return null;
}

export async function scanRemote(
  url: string,
  options: ScanOptions
): Promise<DetectionResult> {
  const config = loadConfig(options.configPath);
  const limiter = new ConcurrencyLimiter(options.concurrency);
  
  const result: DetectionResult = {
    target: url,
    timestamp: new Date().toISOString(),
    source: 'remote',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  // Find active base URL and get HTML
  const found = await findActiveBaseUrl(url, options, limiter);
  if (!found) {
    result.errors.push('Could not connect to the site or WordPress not detected');
    return result;
  }
  
  const { baseUrl, html } = found;
  
  // Detect core
  try {
    result.core = await detectWordPressCore(baseUrl, html, options, limiter) ?? undefined;
    if (!result.core) {
      result.errors.push('WordPress not detected at this URL');
      return result;
    }
  } catch (e) {
    result.errors.push(`Core detection failed: ${e}`);
    return result;
  }
  
  // Extract plugins/themes from HTML
  const htmlPlugins = extractPluginsFromHtml(html);
  const htmlThemes = extractThemesFromHtml(html);
  
  // Extract plugin versions from ?ver= parameters
  const verParamVersions = extractPluginVersionsFromVerParam(html);
  
  // Merge with common lists
  const pluginsToScan = new Set([
    ...getPluginsToScan(config),
    ...htmlPlugins,
  ]);
  
  const themesToScan = new Set([
    ...getThemesToScan(config),
    ...htmlThemes,
  ]);
  
  // Scan plugins with concurrency control
  const pluginPromises = Array.from(pluginsToScan).map(slug =>
    detectPlugin(baseUrl, slug, options, limiter, config, verParamVersions).catch(() => null)
  );
  const pluginResults = await Promise.all(pluginPromises);
  result.plugins = pluginResults.filter((p): p is DetectedComponent => p !== null);
  
  // Scan themes with concurrency control
  const themePromises = Array.from(themesToScan).map(slug =>
    detectTheme(baseUrl, slug, options, limiter).catch(() => null)
  );
  const themeResults = await Promise.all(themePromises);
  result.themes = themeResults.filter((t): t is DetectedComponent => t !== null);
  
  return result;
}
