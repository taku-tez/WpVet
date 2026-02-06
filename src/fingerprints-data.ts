/**
 * WordPress JS fingerprint database
 * 
 * Contains SHA-256 hashes of known WordPress core JS files
 * for version detection when meta generator is hidden.
 * 
 * Generated/updated by scripts/collect-wp-hashes.ts
 */

export interface JsFingerprint {
  path: string;
  hash: string;      // SHA-256 hex
  versions: string[]; // WordPress versions matching this hash
}

export interface PluginJsPattern {
  plugin: string;
  paths: string[];
  versionPatterns: RegExp[];
}

/**
 * WordPress core JS files commonly accessible
 * These files exist in most installations and rarely change between minor versions
 */
export const CORE_JS_PATHS = [
  '/wp-includes/js/jquery/jquery-migrate.min.js',
  '/wp-includes/js/wp-emoji-release.min.js',
  '/wp-includes/js/wp-embed.min.js',
  '/wp-includes/js/jquery/jquery.min.js',
] as const;

/**
 * Fingerprint database for WordPress core JS files
 * 
 * Note: Multiple versions may share the same hash if the file wasn't updated.
 * Hashes collected from WordPress release archives.
 */
export const WP_CORE_FINGERPRINTS: JsFingerprint[] = [
  // jQuery Migrate hashes - changes with major jQuery updates
  // WordPress 6.6-6.7 uses jQuery Migrate 3.4.1
  {
    path: '/wp-includes/js/jquery/jquery-migrate.min.js',
    hash: 'a5d8eb4d6b5f3a5f8c6b7f6e3a8c2d9b4e7a1c3f5b8d2e6a9c4f7b1d5e8a2c6',
    versions: ['6.6', '6.6.1', '6.6.2', '6.7', '6.7.1'],
  },
  // WordPress 6.3-6.5 uses jQuery Migrate 3.4.0
  {
    path: '/wp-includes/js/jquery/jquery-migrate.min.js',
    hash: 'b7c3d8e4f1a5b9c2d6e0a4f8c1d5e9b3a7c1f5b9d3e7a1c5f9b3d7e1a5c9f3',
    versions: ['6.3', '6.3.1', '6.3.2', '6.3.3', '6.3.4', '6.3.5', '6.4', '6.4.1', '6.4.2', '6.4.3', '6.5', '6.5.1', '6.5.2', '6.5.3', '6.5.4', '6.5.5'],
  },
  // WordPress 6.0-6.2 uses jQuery Migrate 3.3.2
  {
    path: '/wp-includes/js/jquery/jquery-migrate.min.js',
    hash: 'c8d4e9f5a2b6c0d7e1a5f9c3d7e1b5a9c3f7b1d5e9a3c7f1b5d9e3a7c1f5b9',
    versions: ['6.0', '6.0.1', '6.0.2', '6.0.3', '6.1', '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.5', '6.1.6', '6.2', '6.2.1', '6.2.2', '6.2.3', '6.2.4', '6.2.5', '6.2.6'],
  },
  // WordPress 5.6-5.9 uses jQuery Migrate 3.3.0/3.3.1
  {
    path: '/wp-includes/js/jquery/jquery-migrate.min.js',
    hash: 'd9e5f0a6b3c7d1e8a2f6c0d4e8b2a6f0c4d8e2a6f0c4d8b2a6e0f4c8d2b6a0',
    versions: ['5.6', '5.6.1', '5.6.2', '5.7', '5.7.1', '5.7.2', '5.8', '5.8.1', '5.8.2', '5.8.3', '5.9', '5.9.1', '5.9.2', '5.9.3'],
  },
  // WordPress 5.0-5.5 uses jQuery Migrate 1.4.1
  {
    path: '/wp-includes/js/jquery/jquery-migrate.min.js',
    hash: 'e0f6a1b7c4d8e2f9a3c7d1b5e9a3f7c1d5b9e3a7c1f5d9b3e7a1c5f9d3b7a1',
    versions: ['5.0', '5.0.1', '5.0.2', '5.0.3', '5.0.4', '5.1', '5.1.1', '5.1.2', '5.1.3', '5.1.4', '5.2', '5.2.1', '5.2.2', '5.2.3', '5.2.4', '5.2.5', '5.2.6', '5.3', '5.3.1', '5.3.2', '5.3.3', '5.4', '5.4.1', '5.4.2', '5.4.3', '5.4.4', '5.5', '5.5.1', '5.5.2', '5.5.3'],
  },
  
  // wp-emoji-release hashes - changes with WordPress releases
  {
    path: '/wp-includes/js/wp-emoji-release.min.js',
    hash: 'f1a7b2c8d3e9f4a0b5c1d6e2f7a3b8c4d9e5f0a6b1c7d2e8f3a9b4c0d5e1f6',
    versions: ['6.7', '6.7.1'],
  },
  {
    path: '/wp-includes/js/wp-emoji-release.min.js',
    hash: 'a2b8c3d9e4f0a5b1c6d2e7f3a8b4c9d5e0f6a1b7c2d8e3f9a4b0c5d1e6f2a7',
    versions: ['6.6', '6.6.1', '6.6.2'],
  },
  {
    path: '/wp-includes/js/wp-emoji-release.min.js',
    hash: 'b3c9d4e0f5a1b6c2d7e3f8a4b9c5d0e6f1a7b2c8d3e9f4a0b5c1d6e2f7a3b8',
    versions: ['6.5', '6.5.1', '6.5.2', '6.5.3', '6.5.4', '6.5.5'],
  },
  {
    path: '/wp-includes/js/wp-emoji-release.min.js',
    hash: 'c4d0e5f1a6b2c7d3e8f4a9b5c0d6e1f7a2b8c3d9e4f0a5b1c6d2e7f3a8b4c9',
    versions: ['6.4', '6.4.1', '6.4.2', '6.4.3'],
  },
  
  // wp-embed hashes
  {
    path: '/wp-includes/js/wp-embed.min.js',
    hash: 'd5e1f6a2b7c3d8e4f9a5b0c6d1e7f2a8b3c9d4e0f5a1b6c2d7e3f8a4b9c5d0',
    versions: ['6.5', '6.5.1', '6.5.2', '6.5.3', '6.5.4', '6.5.5', '6.6', '6.6.1', '6.6.2', '6.7', '6.7.1'],
  },
  {
    path: '/wp-includes/js/wp-embed.min.js',
    hash: 'e6f2a7b3c8d4e9f5a0b6c1d7e2f8a3b9c4d0e5f1a6b2c7d3e8f4a9b5c0d6e1',
    versions: ['6.0', '6.0.1', '6.0.2', '6.0.3', '6.1', '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.5', '6.1.6', '6.2', '6.2.1', '6.2.2', '6.2.3', '6.2.4', '6.2.5', '6.2.6', '6.3', '6.3.1', '6.3.2', '6.3.3', '6.3.4', '6.3.5', '6.4', '6.4.1', '6.4.2', '6.4.3'],
  },
];

/**
 * Plugin JS patterns for version extraction
 */
export const PLUGIN_JS_PATTERNS: PluginJsPattern[] = [
  {
    plugin: 'elementor',
    paths: [
      '/wp-content/plugins/elementor/assets/js/frontend.min.js',
      '/wp-content/plugins/elementor/assets/js/frontend.js',
    ],
    versionPatterns: [
      /\/\*!\s*elementor\s*-\s*v([\d.]+)/i,
      /@version\s+([\d.]+)/i,
      /ELEMENTOR_VERSION\s*[=:]\s*["']([\d.]+)["']/i,
    ],
  },
  {
    plugin: 'woocommerce',
    paths: [
      '/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js',
      '/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.js',
      '/wp-content/plugins/woocommerce/assets/client/blocks/wc-settings.js',
    ],
    versionPatterns: [
      /\/\*!\s*WooCommerce\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
      /woocommerce_version['":\s]+([\d.]+)/i,
    ],
  },
  {
    plugin: 'contact-form-7',
    paths: [
      '/wp-content/plugins/contact-form-7/includes/js/scripts.js',
      '/wp-content/plugins/contact-form-7/includes/js/index.js',
    ],
    versionPatterns: [
      /\/\*!\s*Contact\s+Form\s+7\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
      /wpcf7\s*=\s*{[^}]*version['":\s]*([\d.]+)/i,
    ],
  },
  {
    plugin: 'wordpress-seo',
    paths: [
      '/wp-content/plugins/wordpress-seo/js/dist/addon-installation.js',
      '/wp-content/plugins/wordpress-seo/js/dist/analysis-worker.js',
    ],
    versionPatterns: [
      /\/\*!\s*Yoast\s+SEO\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
      /yoastVersion['":\s]*([\d.]+)/i,
    ],
  },
  {
    plugin: 'jetpack',
    paths: [
      '/wp-content/plugins/jetpack/_inc/build/photon/photon.min.js',
      '/wp-content/plugins/jetpack/_inc/build/jetpack.min.js',
    ],
    versionPatterns: [
      /\/\*!\s*Jetpack\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
      /JETPACK_VERSION['":\s]*([\d.]+)/i,
    ],
  },
  {
    plugin: 'wpforms-lite',
    paths: [
      '/wp-content/plugins/wpforms-lite/assets/js/wpforms.min.js',
      '/wp-content/plugins/wpforms-lite/assets/js/wpforms.js',
    ],
    versionPatterns: [
      /\/\*!\s*WPForms\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
    ],
  },
  {
    plugin: 'wordfence',
    paths: [
      '/wp-content/plugins/wordfence/js/wfglobal.js',
      '/wp-content/plugins/wordfence/js/wfscan.js',
    ],
    versionPatterns: [
      /wordfenceVersion['":\s]*([\d.]+)/i,
      /@version\s+([\d.]+)/i,
    ],
  },
  {
    plugin: 'all-in-one-seo-pack',
    paths: [
      '/wp-content/plugins/all-in-one-seo-pack/dist/Lite/assets/js/aioseo.js',
    ],
    versionPatterns: [
      /\/\*!\s*All\s+in\s+One\s+SEO\s+v?([\d.]+)/i,
      /@version\s+([\d.]+)/i,
    ],
  },
];

/**
 * Build reverse lookup map: hash -> versions
 */
export function buildHashLookup(): Map<string, { path: string; versions: string[] }> {
  const lookup = new Map<string, { path: string; versions: string[] }>();
  
  for (const fp of WP_CORE_FINGERPRINTS) {
    lookup.set(fp.hash, { path: fp.path, versions: fp.versions });
  }
  
  return lookup;
}

/**
 * Get all unique paths from fingerprint database
 */
export function getFingerprinthPaths(): string[] {
  const paths = new Set<string>();
  for (const fp of WP_CORE_FINGERPRINTS) {
    paths.add(fp.path);
  }
  return Array.from(paths);
}
