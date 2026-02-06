/**
 * Plugin-specific vulnerability pattern detection - v0.4.0
 * 
 * Detects known vulnerability patterns in popular WordPress plugins:
 * - Contact Form 7: File upload vulnerabilities
 * - WooCommerce: API exposure, order leaks
 * - Elementor: XSS patterns
 * - All in One SEO: Auth bypass
 * - WPForms: Upload directory exposure
 * - UpdraftPlus: Backup file exposure
 * - Wordfence: Log file exposure
 */

import type { PluginVulnCheck, MisconfigResult, ScanOptions, DetectedComponent } from './types.js';

/**
 * Fetch with timeout and custom headers
 */
async function fetchWithTimeout(
  url: string,
  options: ScanOptions,
  init?: RequestInit
): Promise<Response | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': options.userAgent },
      redirect: 'follow',
      ...init,
    });
    return response;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

// =============================================================================
// Contact Form 7 Vulnerability Checks
// =============================================================================

const cf7FileUploadCheck: PluginVulnCheck = {
  pluginSlug: 'contact-form-7',
  vulnId: 'cf7-unrestricted-upload',
  name: 'Contact Form 7 - Unrestricted File Upload',
  description: 'Contact Form 7 versions < 5.3.2 may allow unrestricted file uploads',
  severity: 'high',
  async check(baseUrl, options) {
    // Check for vulnerable upload paths
    const uploadPaths = [
      '/wp-content/uploads/wpcf7_uploads/',
      '/wp-content/wpcf7_uploads/',
    ];
    
    for (const path of uploadPaths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        // Check for directory listing or file presence
        if (html.includes('Index of') || html.includes('Parent Directory') ||
            html.includes('.php') || html.includes('.phtml')) {
          return {
            id: this.vulnId,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `Upload directory accessible: ${path}`,
            recommendation: 'Update Contact Form 7 to latest version. Block direct access to upload directory.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// WooCommerce Vulnerability Checks
// =============================================================================

const wooApiExposureCheck: PluginVulnCheck = {
  pluginSlug: 'woocommerce',
  vulnId: 'woo-api-exposure',
  name: 'WooCommerce - REST API Exposure',
  description: 'WooCommerce REST API endpoints may expose sensitive order/customer data',
  severity: 'high',
  async check(baseUrl, options) {
    const endpoints = [
      '/wp-json/wc/v3/orders',
      '/wp-json/wc/v2/orders',
      '/wp-json/wc/v3/customers',
      '/wp-json/wc/v2/customers',
      '/wp-json/wc/v3/products',
    ];
    
    const exposedEndpoints: string[] = [];
    
    for (const endpoint of endpoints) {
      const url = `${baseUrl}${endpoint}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        try {
          const json = await response.json();
          // If we get actual data without authentication, it's a problem
          if (Array.isArray(json) && json.length > 0) {
            exposedEndpoints.push(endpoint);
          }
        } catch {
          // Not valid JSON
        }
      }
    }
    
    if (exposedEndpoints.length > 0) {
      const hasOrders = exposedEndpoints.some(e => e.includes('orders'));
      const hasCustomers = exposedEndpoints.some(e => e.includes('customers'));
      
      return {
        id: this.vulnId,
        name: this.name,
        severity: hasOrders || hasCustomers ? 'critical' : 'high',
        description: this.description,
        evidence: `Unauthenticated access to: ${exposedEndpoints.join(', ')}`,
        recommendation: 'Ensure WooCommerce REST API requires authentication. Check API key permissions and disable public access to sensitive endpoints.',
      };
    }
    
    return null;
  },
};

const wooDebugLogCheck: PluginVulnCheck = {
  pluginSlug: 'woocommerce',
  vulnId: 'woo-debug-log',
  name: 'WooCommerce - Debug Log Exposure',
  description: 'WooCommerce debug/log files may be publicly accessible',
  severity: 'medium',
  async check(baseUrl, options) {
    const logPaths = [
      '/wp-content/uploads/wc-logs/',
      '/wp-content/wc-logs/',
      '/wc-logs/',
    ];
    
    for (const path of logPaths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        if (html.includes('Index of') || html.includes('.log') || 
            html.includes('fatal-errors') || html.includes('woocommerce')) {
          return {
            id: this.vulnId,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `Log directory accessible: ${path}`,
            recommendation: 'Block direct access to WooCommerce log directory via .htaccess or server configuration.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// Elementor Vulnerability Checks
// =============================================================================

const elementorXssCheck: PluginVulnCheck = {
  pluginSlug: 'elementor',
  vulnId: 'elementor-xss-vuln',
  name: 'Elementor - XSS Vulnerability Pattern',
  description: 'Elementor may be vulnerable to stored XSS via certain widgets',
  severity: 'medium',
  async check(baseUrl, options) {
    // Check for Elementor presence and version
    const response = await fetchWithTimeout(baseUrl, options);
    if (!response?.ok) return null;
    
    const html = await response.text();
    
    // Check for Elementor scripts with version
    const elementorMatch = html.match(/elementor\/assets\/[^"']*\?ver=([\d.]+)/);
    if (elementorMatch) {
      const version = elementorMatch[1];
      // Known vulnerable versions (simplified check)
      const [major, minor] = version.split('.').map(Number);
      
      // Versions before 3.1.4 had XSS issues
      if (major < 3 || (major === 3 && minor < 2)) {
        return {
          id: this.vulnId,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: `Elementor version ${version} may be vulnerable to XSS`,
          recommendation: 'Update Elementor to the latest version.',
        };
      }
    }
    
    return null;
  },
};

// =============================================================================
// All in One SEO Vulnerability Checks
// =============================================================================

const aioseoAuthBypassCheck: PluginVulnCheck = {
  pluginSlug: 'all-in-one-seo-pack',
  vulnId: 'aioseo-auth-bypass',
  name: 'All in One SEO - REST API Exposure',
  description: 'All in One SEO REST API endpoints may be accessible without authentication',
  severity: 'medium',
  async check(baseUrl, options) {
    const endpoints = [
      '/wp-json/aioseo/v1/posts',
      '/wp-json/aioseo/v1/settings',
    ];
    
    for (const endpoint of endpoints) {
      const url = `${baseUrl}${endpoint}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        try {
          const json = await response.json();
          if (json && typeof json === 'object' && !json.code) {
            return {
              id: this.vulnId,
              name: this.name,
              severity: this.severity,
              description: this.description,
              evidence: `REST API endpoint accessible: ${endpoint}`,
              recommendation: 'Update All in One SEO to the latest version. Review REST API permissions.',
            };
          }
        } catch {
          // Not valid JSON
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// WPForms Vulnerability Checks
// =============================================================================

const wpformsUploadCheck: PluginVulnCheck = {
  pluginSlug: 'wpforms-lite',
  vulnId: 'wpforms-upload-exposure',
  name: 'WPForms - Upload Directory Exposure',
  description: 'WPForms upload directory may be publicly accessible',
  severity: 'medium',
  async check(baseUrl, options) {
    const paths = [
      '/wp-content/uploads/wpforms/',
      '/wpforms/',
    ];
    
    for (const path of paths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        if (html.includes('Index of') || html.includes('Parent Directory')) {
          return {
            id: this.vulnId,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `Upload directory accessible: ${path}`,
            recommendation: 'Block direct access to WPForms upload directory.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// UpdraftPlus Vulnerability Checks
// =============================================================================

const updraftBackupCheck: PluginVulnCheck = {
  pluginSlug: 'updraftplus',
  vulnId: 'updraft-backup-exposure',
  name: 'UpdraftPlus - Backup Files Exposed',
  description: 'UpdraftPlus backup files may be publicly accessible',
  severity: 'critical',
  async check(baseUrl, options) {
    const paths = [
      '/wp-content/updraft/',
      '/wp-content/uploads/updraft/',
      '/updraft/',
    ];
    
    for (const path of paths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        if (html.includes('Index of') || html.includes('backup_') || 
            html.includes('.zip') || html.includes('.gz') ||
            html.includes('-db.') || html.includes('-plugins.')) {
          return {
            id: this.vulnId,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `Backup directory accessible: ${path}`,
            recommendation: 'Move UpdraftPlus backups to a secure location outside web root. Block direct access via server configuration.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// Wordfence Vulnerability Checks
// =============================================================================

const wordfenceLogCheck: PluginVulnCheck = {
  pluginSlug: 'wordfence',
  vulnId: 'wordfence-log-exposure',
  name: 'Wordfence - Log Files Exposed',
  description: 'Wordfence log or configuration files may be publicly accessible',
  severity: 'high',
  async check(baseUrl, options) {
    const paths = [
      '/wp-content/wflogs/',
      '/wflogs/',
      '/wp-content/plugins/wordfence/tmp/',
    ];
    
    for (const path of paths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        if (html.includes('Index of') || html.includes('.php') || 
            html.includes('config') || html.includes('.log')) {
          return {
            id: this.vulnId,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `Log directory accessible: ${path}`,
            recommendation: 'Block direct access to Wordfence log directory.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// Yoast SEO Checks
// =============================================================================

const yoastSitemapCheck: PluginVulnCheck = {
  pluginSlug: 'wordpress-seo',
  vulnId: 'yoast-sitemap-info',
  name: 'Yoast SEO - Sitemap Information Disclosure',
  description: 'Yoast SEO sitemap reveals site structure (informational)',
  severity: 'info',
  async check(baseUrl, options) {
    const url = `${baseUrl}/sitemap_index.xml`;
    const response = await fetchWithTimeout(url, options);
    
    if (response?.ok) {
      const xml = await response.text();
      if (xml.includes('yoast') || xml.includes('sitemapindex')) {
        // Count sitemaps
        const sitemapCount = (xml.match(/<sitemap>/g) || []).length;
        return {
          id: this.vulnId,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: `Yoast sitemap available with ${sitemapCount} sub-sitemaps`,
          recommendation: 'Review sitemap contents to ensure no sensitive URLs are exposed.',
        };
      }
    }
    
    return null;
  },
};

// =============================================================================
// All Plugin Vulnerability Checks
// =============================================================================

export const PLUGIN_VULN_CHECKS: PluginVulnCheck[] = [
  cf7FileUploadCheck,
  wooApiExposureCheck,
  wooDebugLogCheck,
  elementorXssCheck,
  aioseoAuthBypassCheck,
  wpformsUploadCheck,
  updraftBackupCheck,
  wordfenceLogCheck,
  yoastSitemapCheck,
];

/**
 * Run plugin vulnerability checks based on detected plugins
 */
export async function runPluginVulnChecks(
  baseUrl: string,
  detectedPlugins: DetectedComponent[],
  options: ScanOptions
): Promise<MisconfigResult[]> {
  const results: MisconfigResult[] = [];
  const normalizedUrl = baseUrl.replace(/\/$/, '');
  const detectedSlugs = new Set(detectedPlugins.map(p => p.slug.toLowerCase()));
  
  // Filter checks to only run for detected plugins
  const relevantChecks = PLUGIN_VULN_CHECKS.filter(check => {
    const pluginSlug = check.pluginSlug.toLowerCase();
    // Check for exact match or partial match (e.g., wpforms matches wpforms-lite)
    return detectedSlugs.has(pluginSlug) || 
           Array.from(detectedSlugs).some(slug => 
             slug.includes(pluginSlug) || pluginSlug.includes(slug)
           );
  });
  
  // Run checks in parallel
  const checkPromises = relevantChecks.map(async (check) => {
    try {
      return await check.check(normalizedUrl, options);
    } catch {
      return null;
    }
  });
  
  const checkResults = await Promise.all(checkPromises);
  
  for (const result of checkResults) {
    if (result) {
      results.push(result);
    }
  }
  
  // Sort by severity
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  
  results.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return results;
}

/**
 * Run all plugin vulnerability checks (regardless of detected plugins)
 * Used for comprehensive security audit
 */
export async function runAllPluginVulnChecks(
  baseUrl: string,
  options: ScanOptions
): Promise<MisconfigResult[]> {
  const results: MisconfigResult[] = [];
  const normalizedUrl = baseUrl.replace(/\/$/, '');
  
  const checkPromises = PLUGIN_VULN_CHECKS.map(async (check) => {
    try {
      return await check.check(normalizedUrl, options);
    } catch {
      return null;
    }
  });
  
  const checkResults = await Promise.all(checkPromises);
  
  for (const result of checkResults) {
    if (result) {
      results.push(result);
    }
  }
  
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  
  results.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return results;
}
