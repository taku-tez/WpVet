/**
 * WordPress misconfiguration detection - v0.4.0
 * 
 * Detects common WordPress security misconfigurations:
 * - Exposed configuration files
 * - Debug mode enabled
 * - Directory listing
 * - XML-RPC enabled
 * - User enumeration
 * - Exposed installation files
 */

import type { MisconfigCheck, MisconfigResult, ScanOptions, AuditResult } from './types.js';

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

/**
 * Check if response looks like directory listing
 */
function isDirectoryListing(html: string): boolean {
  // Apache/Nginx directory listing patterns
  return (
    html.includes('Index of') ||
    html.includes('<title>Index of') ||
    html.includes('Parent Directory') ||
    html.includes('[DIR]') ||
    html.includes('Directory listing') ||
    /<a href="[^"]*\/">[^<]+\/<\/a>/i.test(html)
  );
}

/**
 * Check if wp-config.php content is exposed
 */
function containsWpConfigContent(text: string): boolean {
  return (
    text.includes('DB_NAME') ||
    text.includes('DB_USER') ||
    text.includes('DB_PASSWORD') ||
    text.includes('DB_HOST') ||
    text.includes("define('DB_") ||
    text.includes('define("DB_') ||
    text.includes('$table_prefix') ||
    text.includes('ABSPATH')
  );
}

// =============================================================================
// Misconfiguration Checks
// =============================================================================

const wpConfigExposedCheck: MisconfigCheck = {
  id: 'wp-config-exposed',
  name: 'wp-config.php Exposed',
  description: 'WordPress configuration file is publicly accessible, potentially exposing database credentials',
  severity: 'critical',
  async check(baseUrl, options) {
    const files = [
      '/wp-config.php',
      '/wp-config.php.bak',
      '/wp-config.php~',
      '/wp-config.php.old',
      '/wp-config.php.save',
      '/wp-config.php.swp',
      '/wp-config.php.orig',
      '/wp-config.bak',
      '/wp-config.txt',
    ];
    
    for (const file of files) {
      const url = `${baseUrl}${file}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const text = await response.text();
        if (containsWpConfigContent(text)) {
          return {
            id: this.id,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `${file} returned HTTP 200 with database credentials`,
            recommendation: 'Remove backup files and ensure wp-config.php is not directly accessible. Configure server to deny access to .php files in root.',
          };
        }
      }
    }
    
    return null;
  },
};

const debugModeCheck: MisconfigCheck = {
  id: 'debug-mode-enabled',
  name: 'Debug Mode Enabled',
  description: 'WP_DEBUG appears to be enabled, exposing PHP errors and sensitive information',
  severity: 'high',
  async check(baseUrl, options) {
    const response = await fetchWithTimeout(baseUrl, options);
    if (!response?.ok) return null;
    
    const html = await response.text();
    
    // PHP error patterns
    const debugPatterns = [
      /Fatal error:/i,
      /Warning:/i,
      /Notice:/i,
      /Parse error:/i,
      /Deprecated:/i,
      /Strict Standards:/i,
      /on line \d+/i,
      /Stack trace:/i,
      /WP_DEBUG/,
      /xdebug/i,
    ];
    
    const matches: string[] = [];
    for (const pattern of debugPatterns) {
      if (pattern.test(html)) {
        const match = html.match(pattern);
        if (match) matches.push(match[0]);
      }
    }
    
    if (matches.length > 0) {
      return {
        id: this.id,
        name: this.name,
        severity: this.severity,
        description: this.description,
        evidence: `Found debug indicators: ${matches.slice(0, 3).join(', ')}`,
        recommendation: 'Set WP_DEBUG to false in wp-config.php for production sites. Use WP_DEBUG_LOG to log errors to a file instead.',
      };
    }
    
    return null;
  },
};

const directoryListingCheck: MisconfigCheck = {
  id: 'directory-listing',
  name: 'Directory Listing Enabled',
  description: 'Server directory listing is enabled, exposing file structure',
  severity: 'medium',
  async check(baseUrl, options) {
    const dirs = [
      '/wp-content/uploads/',
      '/wp-content/plugins/',
      '/wp-content/themes/',
      '/wp-includes/',
      '/wp-content/upgrade/',
      '/wp-content/cache/',
    ];
    
    const exposedDirs: string[] = [];
    
    for (const dir of dirs) {
      const url = `${baseUrl}${dir}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const html = await response.text();
        if (isDirectoryListing(html)) {
          exposedDirs.push(dir);
        }
      }
    }
    
    if (exposedDirs.length > 0) {
      return {
        id: this.id,
        name: this.name,
        severity: this.severity,
        description: this.description,
        evidence: `Directory listing enabled: ${exposedDirs.join(', ')}`,
        recommendation: 'Add "Options -Indexes" to .htaccess or configure nginx to disable autoindex.',
      };
    }
    
    return null;
  },
};

const xmlrpcEnabledCheck: MisconfigCheck = {
  id: 'xmlrpc-enabled',
  name: 'XML-RPC Enabled',
  description: 'XML-RPC is enabled and accessible, potentially allowing brute-force attacks',
  severity: 'medium',
  async check(baseUrl, options) {
    const url = `${baseUrl}/xmlrpc.php`;
    
    // First check if xmlrpc.php exists
    const headResponse = await fetchWithTimeout(url, options, { method: 'HEAD' });
    if (!headResponse || headResponse.status === 404) return null;
    
    // Try to call system.listMethods
    const body = `<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`;
    
    const response = await fetchWithTimeout(url, options, {
      method: 'POST',
      headers: { 'Content-Type': 'text/xml' },
      body,
    });
    
    if (response?.ok) {
      const text = await response.text();
      if (text.includes('methodResponse') && text.includes('wp.')) {
        const methodCount = (text.match(/<string>wp\./g) || []).length;
        return {
          id: this.id,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: `XML-RPC responds to system.listMethods (${methodCount} wp.* methods available)`,
          recommendation: 'Disable XML-RPC if not needed. Use a security plugin or add to .htaccess: <Files xmlrpc.php>Order Deny,Allow Deny from all</Files>',
        };
      }
    }
    
    return null;
  },
};

const readmeExposedCheck: MisconfigCheck = {
  id: 'readme-exposed',
  name: 'readme.html Exposed',
  description: 'WordPress readme.html is accessible, revealing version information',
  severity: 'low',
  async check(baseUrl, options) {
    const url = `${baseUrl}/readme.html`;
    const response = await fetchWithTimeout(url, options);
    
    if (response?.ok) {
      const html = await response.text();
      const versionMatch = html.match(/Version\s+([\d.]+)/i);
      
      if (html.includes('WordPress') || versionMatch) {
        return {
          id: this.id,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: versionMatch ? `Exposes WordPress version: ${versionMatch[1]}` : 'readme.html accessible',
          recommendation: 'Delete readme.html from WordPress root directory or block access via server configuration.',
        };
      }
    }
    
    return null;
  },
};

const licenseExposedCheck: MisconfigCheck = {
  id: 'license-exposed',
  name: 'license.txt Exposed',
  description: 'WordPress license.txt is accessible, confirming WordPress installation',
  severity: 'info',
  async check(baseUrl, options) {
    const url = `${baseUrl}/license.txt`;
    const response = await fetchWithTimeout(url, options);
    
    if (response?.ok) {
      const text = await response.text();
      if (text.includes('WordPress') || text.includes('GNU General Public License')) {
        return {
          id: this.id,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: 'license.txt accessible, confirms WordPress installation',
          recommendation: 'Delete license.txt or block access if security through obscurity is desired.',
        };
      }
    }
    
    return null;
  },
};

const installPhpCheck: MisconfigCheck = {
  id: 'install-php-accessible',
  name: 'install.php Accessible',
  description: 'WordPress installation script is accessible, potential security risk',
  severity: 'high',
  async check(baseUrl, options) {
    const url = `${baseUrl}/wp-admin/install.php`;
    const response = await fetchWithTimeout(url, options);
    
    if (response?.ok) {
      const html = await response.text();
      // Check if it's the actual install page, not a redirect to wp-login
      if (html.includes('Welcome') && html.includes('WordPress') && 
          (html.includes('installation') || html.includes('install'))) {
        return {
          id: this.id,
          name: this.name,
          severity: this.severity,
          description: this.description,
          evidence: 'install.php returns installation page',
          recommendation: 'Delete wp-admin/install.php after installation or ensure WordPress is fully configured.',
        };
      }
      
      // Already installed but accessible
      if (html.includes('already installed') || html.includes('You appear to have already installed')) {
        return {
          id: this.id,
          name: 'install.php Accessible (Low Risk)',
          severity: 'info',
          description: 'WordPress installation script is accessible but WordPress is already installed',
          evidence: 'install.php accessible but shows "already installed" message',
          recommendation: 'Consider deleting wp-admin/install.php or blocking access.',
        };
      }
    }
    
    return null;
  },
};

const userEnumerationCheck: MisconfigCheck = {
  id: 'user-enumeration',
  name: 'User Enumeration Possible',
  description: 'User enumeration is possible via author archives or REST API',
  severity: 'medium',
  async check(baseUrl, options) {
    const findings: string[] = [];
    
    // Check author archive redirect
    const authorUrl = `${baseUrl}/?author=1`;
    const authorResponse = await fetchWithTimeout(authorUrl, options, { redirect: 'manual' });
    
    if (authorResponse?.status === 301 || authorResponse?.status === 302) {
      const location = authorResponse.headers.get('location');
      if (location && location.includes('/author/')) {
        const username = location.match(/\/author\/([^\/]+)/)?.[1];
        findings.push(`Author redirect reveals username${username ? `: ${username}` : ''}`);
      }
    }
    
    // Check REST API users endpoint
    const usersUrl = `${baseUrl}/wp-json/wp/v2/users`;
    const usersResponse = await fetchWithTimeout(usersUrl, options);
    
    if (usersResponse?.ok) {
      try {
        const users = await usersResponse.json();
        if (Array.isArray(users) && users.length > 0) {
          const usernames = users.slice(0, 3).map((u: { slug?: string }) => u.slug).filter(Boolean);
          findings.push(`REST API exposes ${users.length} user(s)${usernames.length ? `: ${usernames.join(', ')}` : ''}`);
        }
      } catch {
        // Not valid JSON
      }
    }
    
    if (findings.length > 0) {
      return {
        id: this.id,
        name: this.name,
        severity: this.severity,
        description: this.description,
        evidence: findings.join('; '),
        recommendation: 'Disable author archives or use a security plugin to block user enumeration. Consider disabling REST API user endpoint.',
      };
    }
    
    return null;
  },
};

const wpIncludesExposedCheck: MisconfigCheck = {
  id: 'wp-includes-exposed',
  name: 'wp-includes Directory Exposed',
  description: 'Direct access to wp-includes files reveals WordPress internals',
  severity: 'low',
  async check(baseUrl, options) {
    const testFiles = [
      '/wp-includes/version.php',
      '/wp-includes/wp-db.php',
    ];
    
    for (const file of testFiles) {
      const url = `${baseUrl}${file}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const text = await response.text();
        // Check if PHP source is exposed (misconfigured server)
        if (text.includes('<?php') || text.includes('$wp_version')) {
          return {
            id: this.id,
            name: this.name,
            severity: 'critical',
            description: 'PHP source code is exposed due to misconfigured server',
            evidence: `${file} exposes PHP source code`,
            recommendation: 'Ensure PHP is properly configured to execute .php files, not serve them as text.',
          };
        }
      }
    }
    
    return null;
  },
};

const htaccessExposedCheck: MisconfigCheck = {
  id: 'htaccess-exposed',
  name: '.htaccess Exposed',
  description: '.htaccess file is publicly accessible',
  severity: 'high',
  async check(baseUrl, options) {
    const files = ['/.htaccess', '/wp-admin/.htaccess', '/wp-content/.htaccess'];
    
    for (const file of files) {
      const url = `${baseUrl}${file}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const text = await response.text();
        if (text.includes('RewriteRule') || text.includes('RewriteEngine') || 
            text.includes('AuthType') || text.includes('Order') || text.includes('<Files')) {
          return {
            id: this.id,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `${file} is publicly accessible`,
            recommendation: 'Configure server to deny access to .htaccess files.',
          };
        }
      }
    }
    
    return null;
  },
};

const debugLogExposedCheck: MisconfigCheck = {
  id: 'debug-log-exposed',
  name: 'Debug Log Exposed',
  description: 'WordPress debug log file is publicly accessible',
  severity: 'high',
  async check(baseUrl, options) {
    const logPaths = [
      '/wp-content/debug.log',
      '/debug.log',
      '/wp-content/uploads/debug.log',
    ];
    
    for (const path of logPaths) {
      const url = `${baseUrl}${path}`;
      const response = await fetchWithTimeout(url, options);
      
      if (response?.ok) {
        const text = await response.text();
        // Check for typical PHP error log content
        if (text.includes('[') && (text.includes('PHP') || text.includes('WordPress') || 
            text.includes('error') || text.includes('Notice') || text.includes('Warning'))) {
          return {
            id: this.id,
            name: this.name,
            severity: this.severity,
            description: this.description,
            evidence: `${path} is publicly accessible`,
            recommendation: 'Move debug.log outside web root or block access via server configuration. Set WP_DEBUG_LOG to a path outside web root.',
          };
        }
      }
    }
    
    return null;
  },
};

// =============================================================================
// All Checks
// =============================================================================

export const MISCONFIG_CHECKS: MisconfigCheck[] = [
  wpConfigExposedCheck,
  debugModeCheck,
  debugLogExposedCheck,
  htaccessExposedCheck,
  directoryListingCheck,
  xmlrpcEnabledCheck,
  readmeExposedCheck,
  licenseExposedCheck,
  installPhpCheck,
  userEnumerationCheck,
  wpIncludesExposedCheck,
];

/**
 * Run all misconfiguration checks
 */
export async function runMisconfigChecks(
  baseUrl: string,
  options: ScanOptions
): Promise<MisconfigResult[]> {
  const results: MisconfigResult[] = [];
  const normalizedUrl = baseUrl.replace(/\/$/, '');
  
  // Run checks in parallel with error handling
  const checkPromises = MISCONFIG_CHECKS.map(async (check) => {
    try {
      const result = await check.check(normalizedUrl, options);
      return result;
    } catch {
      // Silently skip failed checks
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
 * Run audit scan (misconfigs only)
 */
export async function runAudit(
  url: string,
  options: ScanOptions
): Promise<AuditResult> {
  const result: AuditResult = {
    target: url,
    timestamp: new Date().toISOString(),
    misconfigs: [],
    pluginVulns: [],
    errors: [],
  };
  
  try {
    result.misconfigs = await runMisconfigChecks(url, options);
  } catch (e) {
    result.errors.push(`Audit failed: ${e instanceof Error ? e.message : e}`);
  }
  
  return result;
}
