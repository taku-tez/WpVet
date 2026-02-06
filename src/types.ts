/**
 * WpVet type definitions - v0.3.0
 */

export interface WpPlugin {
  name: string;
  slug: string;
  version: string;
  status: 'active' | 'inactive' | 'must-use' | 'dropin';
  update?: 'available' | 'none';
  auto_update?: 'on' | 'off';
  title?: string;
  author?: string;
  description?: string;
}

export interface WpTheme {
  name: string;
  slug: string;
  version: string;
  status: 'active' | 'inactive' | 'parent';
  update?: 'available' | 'none';
  auto_update?: 'on' | 'off';
  title?: string;
  author?: string;
}

export interface WpCore {
  version: string;
  site_url?: string;
  home_url?: string;
  multisite?: boolean;
}

export interface WpCliInput {
  core?: WpCore;
  plugins?: WpPlugin[];
  themes?: WpTheme[];
}

export interface DetectedComponent {
  type: 'core' | 'plugin' | 'theme';
  slug: string;
  name: string;
  version: string;
  status?: string;
  update?: 'available' | 'none';
  auto_update?: 'on' | 'off';
  cpe: string;
  confidence: number;  // 0-100
  source: 'wp-cli' | 'remote' | 'local';
}

export interface SiteInfo {
  site_url?: string;
  home_url?: string;
  multisite?: boolean;
}

export interface DetectionResult {
  target: string;
  timestamp: string;
  source: 'wp-cli' | 'remote' | 'local';
  core?: DetectedComponent;
  plugins: DetectedComponent[];
  themes: DetectedComponent[];
  errors: string[];
  site?: SiteInfo;
}

export interface ScanOptions {
  format: 'cpe' | 'json' | 'table';
  stdin: boolean;
  timeout: number;
  userAgent: string;
  verbose: boolean;
  // v0.3.0: New options
  concurrency: number;      // Max concurrent requests
  retry: number;            // Retry count for failed requests
  retryDelay: number;       // Base delay between retries (ms)
  configPath?: string;      // Path to config file
}

export const DEFAULT_OPTIONS: ScanOptions = {
  format: 'table',
  stdin: false,
  timeout: 30000,
  userAgent: 'WpVet/0.3.0 (Security Scanner)',
  verbose: false,
  concurrency: 5,
  retry: 2,
  retryDelay: 1000,
};

/** Exit codes */
export const EXIT_SUCCESS = 0;           // Normal exit, components detected
export const EXIT_NOT_DETECTED = 1;      // WordPress not detected / no components
export const EXIT_ERROR = 2;             // Error occurred
