/**
 * Remote WordPress detection
 */

import type { DetectedComponent, DetectionResult, ScanOptions } from './types.js';
import { generateCoreCpe, generatePluginCpe, generateThemeCpe } from './cpe.js';

const COMMON_PLUGINS = [
  'contact-form-7',
  'elementor',
  'woocommerce',
  'jetpack',
  'akismet',
  'wordfence',
  'yoast-seo',
  'wordpress-seo',
  'wpforms-lite',
  'classic-editor',
  'really-simple-ssl',
  'all-in-one-seo-pack',
  'updraftplus',
  'wp-super-cache',
  'w3-total-cache',
  'litespeed-cache',
  'advanced-custom-fields',
];

const COMMON_THEMES = [
  'twentytwentyfour',
  'twentytwentythree',
  'twentytwentytwo',
  'twentytwentyone',
  'astra',
  'oceanwp',
  'generatepress',
  'neve',
];

async function fetchWithTimeout(
  url: string,
  options: ScanOptions
): Promise<Response | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': options.userAgent },
    });
    return response;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

function extractVersion(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) return match[1];
  }
  return null;
}

export async function detectWordPressCore(
  baseUrl: string,
  options: ScanOptions
): Promise<DetectedComponent | null> {
  const response = await fetchWithTimeout(baseUrl, options);
  if (!response) return null;
  
  const html = await response.text();
  
  // Check meta generator
  const generatorMatch = html.match(
    /<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)?["']/i
  );
  
  if (generatorMatch) {
    const version = generatorMatch[1] || 'unknown';
    return {
      type: 'core',
      slug: 'wordpress',
      name: 'WordPress',
      version,
      cpe: generateCoreCpe(version),
      confidence: version === 'unknown' ? 60 : 90,
      source: 'remote',
    };
  }
  
  // Check wp-includes paths
  if (html.includes('/wp-includes/') || html.includes('/wp-content/')) {
    return {
      type: 'core',
      slug: 'wordpress',
      name: 'WordPress',
      version: 'unknown',
      cpe: generateCoreCpe('unknown'),
      confidence: 50,
      source: 'remote',
    };
  }
  
  return null;
}

export async function detectPlugin(
  baseUrl: string,
  slug: string,
  options: ScanOptions
): Promise<DetectedComponent | null> {
  const readmeUrl = `${baseUrl}/wp-content/plugins/${slug}/readme.txt`;
  const response = await fetchWithTimeout(readmeUrl, options);
  
  if (!response?.ok) return null;
  
  const text = await response.text();
  const version = extractVersion(text, [
    /Stable tag:\s*([0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?)/i,
    /Version:\s*([0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?)/i,
  ]);
  
  if (version) {
    return {
      type: 'plugin',
      slug,
      name: slug,
      version,
      cpe: generatePluginCpe(slug, version),
      confidence: 85,
      source: 'remote',
    };
  }
  
  return null;
}

export async function detectTheme(
  baseUrl: string,
  slug: string,
  options: ScanOptions
): Promise<DetectedComponent | null> {
  const styleUrl = `${baseUrl}/wp-content/themes/${slug}/style.css`;
  const response = await fetchWithTimeout(styleUrl, options);
  
  if (!response?.ok) return null;
  
  const text = await response.text();
  const version = extractVersion(text, [
    /Version:\s*([0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?)/i,
  ]);
  
  if (version) {
    return {
      type: 'theme',
      slug,
      name: slug,
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
  const normalizedUrl = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  const baseUrl = normalizedUrl.replace(/\/$/, '');
  const result: DetectionResult = {
    target: normalizedUrl,
    timestamp: new Date().toISOString(),
    source: 'remote',
    plugins: [],
    themes: [],
    errors: [],
  };
  
  // Detect core
  try {
    result.core = await detectWordPressCore(baseUrl, options) ?? undefined;
    if (!result.core) {
      result.errors.push('WordPress not detected at this URL');
      return result;
    }
  } catch (e) {
    result.errors.push(`Core detection failed: ${e}`);
    return result;
  }
  
  // Scan common plugins (parallel, limited concurrency)
  const pluginPromises = COMMON_PLUGINS.map(slug =>
    detectPlugin(baseUrl, slug, options).catch(() => null)
  );
  const pluginResults = await Promise.all(pluginPromises);
  result.plugins = pluginResults.filter((p): p is DetectedComponent => p !== null);
  
  // Scan common themes
  const themePromises = COMMON_THEMES.map(slug =>
    detectTheme(baseUrl, slug, options).catch(() => null)
  );
  const themeResults = await Promise.all(themePromises);
  result.themes = themeResults.filter((t): t is DetectedComponent => t !== null);
  
  return result;
}
