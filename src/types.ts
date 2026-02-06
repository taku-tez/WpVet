/**
 * WpVet type definitions
 */

import { USER_AGENT } from './version.js';

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
  cpe: string;
  confidence: number;  // 0-100
  source: 'wp-cli' | 'remote' | 'local';
}

export interface DetectionResult {
  target: string;
  timestamp: string;
  source: 'wp-cli' | 'remote' | 'local';
  core?: DetectedComponent;
  plugins: DetectedComponent[];
  themes: DetectedComponent[];
  errors: string[];
}

export interface ScanOptions {
  format: 'cpe' | 'json' | 'table';
  stdin: boolean;
  timeout: number;
  userAgent: string;
  verbose: boolean;
}

export const DEFAULT_OPTIONS: ScanOptions = {
  format: 'table',
  stdin: false,
  timeout: 30000,
  userAgent: USER_AGENT,
  verbose: false,
};
