/**
 * WpVet configuration management
 * 
 * Config file locations (in priority order):
 * 1. --config <path> CLI option
 * 2. ~/.wpvet/config.json
 * 3. Built-in defaults
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface WpVetConfig {
  /** Additional plugins to scan for (merged with built-in list) */
  additionalPlugins?: string[];
  /** Additional themes to scan for (merged with built-in list) */
  additionalThemes?: string[];
  /** Custom plugins list (replaces built-in if provided) */
  customPlugins?: string[];
  /** Custom themes list (replaces built-in if provided) */
  customThemes?: string[];
  /** Default user agent */
  userAgent?: string;
  /** Default timeout in ms */
  timeout?: number;
  /** Default concurrency */
  concurrency?: number;
  /** Known plugin vendor mappings: slug -> vendor */
  pluginVendors?: Record<string, string>;
}

/** Built-in common plugins to scan */
export const BUILTIN_PLUGINS = [
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
  'redirection',
  'duplicate-post',
  'google-analytics-for-wordpress',
  'google-site-kit',
  'wp-mail-smtp',
  'all-in-one-wp-migration',
  'tablepress',
  'ninja-forms',
  'gravityforms',
  'wpcf7-recaptcha',
  'cookie-notice',
  'cookiebot',
  'wp-fastest-cache',
  'autoptimize',
];

/** Built-in common themes to scan */
export const BUILTIN_THEMES = [
  'twentytwentyfive',
  'twentytwentyfour',
  'twentytwentythree',
  'twentytwentytwo',
  'twentytwentyone',
  'twentytwenty',
  'twentynineteen',
  'twentyseventeen',
  'twentysixteen',
  'twentyfifteen',
  'astra',
  'oceanwp',
  'generatepress',
  'neve',
  'flavor',
  'flavor-developer',
  'flavor-developer-developer',
  'flavor-developer-developer-developer',
  'flavor-developer-developer-developer-developer',
];

/** Known plugin vendor mappings for accurate CPE generation */
export const KNOWN_PLUGIN_VENDORS: Record<string, string> = {
  'contact-form-7': 'rocklobster',
  'elementor': 'developer',
  'woocommerce': 'automattic',
  'jetpack': 'automattic',
  'akismet': 'automattic',
  'wordfence': 'wordfence',
  'yoast-seo': 'yoast',
  'wordpress-seo': 'yoast',
  'wpforms-lite': 'wpforms',
  'really-simple-ssl': 'really-simple-plugins',
  'all-in-one-seo-pack': 'developer',
  'updraftplus': 'developer',
  'advanced-custom-fields': 'developer',
  'google-site-kit': 'developer',
  'wp-mail-smtp': 'developer',
  'gravityforms': 'developer',
};

function getDefaultConfigPath(): string {
  return join(homedir(), '.wpvet', 'config.json');
}

/**
 * Load configuration from file
 */
export function loadConfig(configPath?: string): WpVetConfig {
  const paths = [
    configPath,
    getDefaultConfigPath(),
  ].filter(Boolean) as string[];
  
  for (const path of paths) {
    if (existsSync(path)) {
      try {
        const content = readFileSync(path, 'utf8');
        return JSON.parse(content) as WpVetConfig;
      } catch {
        // Ignore parse errors, continue to next
      }
    }
  }
  
  return {};
}

/**
 * Get effective plugins list
 */
export function getPluginsToScan(config: WpVetConfig): string[] {
  if (config.customPlugins && config.customPlugins.length > 0) {
    return config.customPlugins;
  }
  
  const plugins = [...BUILTIN_PLUGINS];
  if (config.additionalPlugins) {
    for (const plugin of config.additionalPlugins) {
      if (!plugins.includes(plugin)) {
        plugins.push(plugin);
      }
    }
  }
  
  return plugins;
}

/**
 * Get effective themes list
 */
export function getThemesToScan(config: WpVetConfig): string[] {
  if (config.customThemes && config.customThemes.length > 0) {
    return config.customThemes;
  }
  
  const themes = [...BUILTIN_THEMES];
  if (config.additionalThemes) {
    for (const theme of config.additionalThemes) {
      if (!themes.includes(theme)) {
        themes.push(theme);
      }
    }
  }
  
  return themes;
}

/**
 * Get vendor for a plugin slug
 */
export function getPluginVendor(slug: string, config: WpVetConfig): string {
  // Check config overrides first
  if (config.pluginVendors?.[slug]) {
    return config.pluginVendors[slug];
  }
  
  // Check built-in mappings
  if (KNOWN_PLUGIN_VENDORS[slug]) {
    return KNOWN_PLUGIN_VENDORS[slug];
  }
  
  // Fall back to slug as vendor
  return slug;
}

/**
 * Initialize default config file
 */
export function initConfig(): void {
  const configDir = join(homedir(), '.wpvet');
  const configPath = join(configDir, 'config.json');
  
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }

  if (!existsSync(configPath)) {
    const defaultConfig: WpVetConfig = {
      additionalPlugins: [],
      additionalThemes: [],
      pluginVendors: {},
    };
    writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
  }
}
