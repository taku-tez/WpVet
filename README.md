# WpVet v0.4.0

[![npm version](https://img.shields.io/npm/v/wpvet)](https://www.npmjs.com/package/wpvet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

WordPress plugin/theme security scanner with CPE output for vulnerability correlation.

## Features

- **WP-CLI Integration**: 100% accuracy by parsing `wp plugin list --format=json`
- **Remote Detection**: Scan WordPress sites without server access (60-85% accuracy)
- **SSH Scanning**: Direct scanning via SSH + WP-CLI
- **Security Audit**: Detect misconfigurations and plugin-specific vulnerabilities
- **CPE Output**: Standard format for vulnerability database correlation
- **Multiple Output Formats**: CPE, JSON, table
- **Configurable**: Custom plugin/theme lists via config file
- **Concurrent Scanning**: Configurable concurrency with retry support

## Quick Start

```bash
npx wpvet --help
```

## Installation

```bash
npm install -g wpvet
```

## Usage

### Security Audit (NEW in v0.4.0)

Check for WordPress misconfigurations and plugin vulnerabilities:

```bash
# Security audit only
wpvet audit https://example.com

# Security audit with JSON output
wpvet audit https://example.com --format json

# Detection + security audit combined
wpvet detect https://example.com --audit
```

**What it checks:**

| Check | Severity | Description |
|-------|----------|-------------|
| wp-config.php exposed | Critical | Configuration file with DB credentials accessible |
| Debug log exposed | High | PHP error logs publicly accessible |
| Debug mode enabled | High | PHP errors visible in HTML output |
| install.php accessible | High | Installation script still available |
| .htaccess exposed | High | Server configuration file accessible |
| XML-RPC enabled | Medium | Brute-force attack vector |
| Directory listing | Medium | File structure exposed |
| User enumeration | Medium | Username discovery possible |
| readme.html exposed | Low | WordPress version leak |
| license.txt exposed | Info | Confirms WordPress installation |

**Plugin-specific checks:**

| Plugin | Check | Severity |
|--------|-------|----------|
| WooCommerce | REST API order/customer exposure | Critical |
| UpdraftPlus | Backup files accessible | Critical |
| Wordfence | Log files exposed | High |
| Contact Form 7 | Upload directory exposure | High |
| WooCommerce | Debug log exposure | Medium |
| All in One SEO | REST API exposure | Medium |
| WPForms | Upload directory exposure | Medium |
| Elementor | XSS vulnerability pattern | Medium |
| Yoast SEO | Sitemap information disclosure | Info |

### SSH + WP-CLI (Recommended - 100% Accuracy)

Scan remote WordPress sites via SSH:

```bash
# Basic SSH scan
wpvet scan ssh://user@example.com/var/www/wordpress

# With SSH key
wpvet scan ssh://deploy@server.com/home/deploy/wp -k ~/.ssh/id_rsa

# Custom port
wpvet scan ssh://root@example.com:2222/var/www/html

# With WP-CLI path override
wpvet scan "ssh://user@host/var/www?wp-cli=/usr/local/bin/wp"

# CPE output
wpvet scan ssh://user@host/path --format cpe
```

### WP-CLI Integration

On your WordPress server:

```bash
# Scan plugins
wp plugin list --format=json | wpvet detect --stdin --format cpe

# Output:
# cpe:2.3:a:rocklobster:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*
# cpe:2.3:a:developer:elementor:3.18.0:*:*:*:*:wordpress:*:*
```

Combined scan with core, plugins, and themes:

```bash
{
  echo '{"core":{"version":"'$(wp core version)'"},"plugins":'
  wp plugin list --format=json
  echo ',"themes":'
  wp theme list --format=json
  echo '}'
} | wpvet detect --stdin
```

### Remote Detection

```bash
# Basic scan
wpvet detect https://example.com

# With custom options
wpvet detect https://example.com --concurrency 10 --timeout 60000

# Batch scan from file
wpvet detect --targets urls.txt --format cpe

# Batch scan with audit
wpvet detect --targets urls.txt --audit

# CPE output only
wpvet detect https://example.com --format cpe

# JSON output
wpvet detect https://example.com --format json
```

## CLI Options

```
OPTIONS:
  -f, --format <fmt>       Output format: cpe, json, table (default: table)
  -t, --timeout <ms>       Request timeout in milliseconds (default: 30000)
  -k, --ssh-key <path>     SSH private key path
  --wp-cli <path>          WP-CLI binary path (default: wp)
  --user-agent <ua>        Custom User-Agent string
  --concurrency <n>        Max concurrent requests (default: 5)
  --retry <n>              Retry count for failed requests (default: 2)
  --targets <file>         File with target URLs (one per line)
  --config <path>          Path to config file (default: ~/.wpvet/config.json)
  --audit                  Include security audit (misconfigs, plugin vulns)
  -v, --verbose            Verbose output
  -h, --help               Show help
  --version                Show version
```

## Configuration

Initialize config file:

```bash
wpvet init
```

Config file location: `~/.wpvet/config.json`

Option precedence is:

1. CLI option (highest priority)
2. Config file value
3. Built-in default (lowest priority)

Example: `--timeout` is specified on the CLI, that value is used. If `--timeout` is omitted, `timeout` in config is used. If neither is set, the built-in default is used.

```json
{
  "additionalPlugins": ["my-custom-plugin"],
  "additionalThemes": ["my-custom-theme"],
  "pluginVendors": {
    "my-plugin": "mycompany"
  },
  "timeout": 60000,
  "concurrency": 10
}
```

## Output Formats

### CPE Format
```
cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*
cpe:2.3:a:rocklobster:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*
```

### Table Format (default)
```
Target: https://example.com
Scan time: 2024-01-15T10:30:00.000Z
Source: remote

WordPress Core:
  Version: 6.4.2 (confidence: 95%)
  CPE: cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*

Plugins:
  Name                         Version    Status     Update   AutoUpd  Conf
  ---------------------------- ---------- ---------- -------- -------- ----
  contact-form-7               5.7.1      active     No       ✓ On     100%
  elementor                    3.18.0     active     ⚠ Yes    Off      100%

Security Issues:
  Severity   Issue                               Evidence
  ---------- ----------------------------------- ---------------------------------------------
  CRITICAL   wp-config.php Exposed               /wp-config.php.bak returned HTTP 200 with...
  HIGH       XML-RPC Enabled                     system.listMethods available (12 wp.* methods)
  MEDIUM     Directory Listing Enabled           /wp-content/uploads/ lists files

Total: 3 component(s) detected
Security: 3 issue(s) found (1 critical, 1 high)
```

### Audit Output (wpvet audit)

```
Target: https://example.com
Scan time: 2024-01-15T10:30:00.000Z

Security Issues:
  Severity   Issue                               Evidence
  ---------- ----------------------------------- ---------------------------------------------
  CRITICAL   wp-config.php Exposed               /wp-config.php returned HTTP 200 with DB...
  CRITICAL   UpdraftPlus - Backup Files Exposed  Backup directory accessible: /wp-content/...
  HIGH       Debug Log Exposed                   /wp-content/debug.log is publicly accessi...
  MEDIUM     XML-RPC Enabled                     XML-RPC responds to system.listMethods

Summary: 4 issue(s) found
  Critical: 2, High: 1, Medium: 1
```

### JSON Output Schema

```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source": "remote",
  "core": { ... },
  "plugins": [ ... ],
  "themes": [ ... ],
  "misconfigs": [
    {
      "id": "wp-config-exposed",
      "name": "wp-config.php Exposed",
      "severity": "critical",
      "description": "WordPress configuration file is publicly accessible...",
      "evidence": "/wp-config.php returned HTTP 200 with database credentials",
      "recommendation": "Remove backup files and ensure wp-config.php is not directly accessible..."
    }
  ],
  "errors": []
}
```

## Detection Methods

### Remote Detection (wpvet detect)

Version extraction from multiple sources:
- Meta generator tag (confidence: 95%)
- WordPress REST API /wp-json/ (confidence: 70%)
- readme.html version parsing (confidence: 85%)
- Script/style ?ver= parameter extraction (confidence: 80%)
- /wp-content/plugins/\<slug\>/readme.txt probing
- /wp-content/themes/\<slug\>/style.css probing
- HTML parsing for plugin/theme path discovery

### SSH Detection (wpvet scan)

Direct WP-CLI execution:
- wp core version
- wp plugin list --format=json
- wp theme list --format=json
- Automatic WP-CLI path detection
- Automatic WordPress path detection

### Security Audit (wpvet audit)

Misconfiguration checks:
- Configuration file exposure (wp-config.php and backups)
- Debug mode and log file exposure
- Directory listing enabled
- XML-RPC accessibility
- Installation files accessible
- User enumeration via author archives and REST API
- .htaccess file exposure

Plugin-specific vulnerability patterns:
- Checks for known vulnerable configurations per plugin
- Upload directory exposure
- API endpoint exposure without authentication
- Backup file accessibility

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - WordPress detected with components (or audit found issues) |
| 1 | No detection - WordPress not found or no components/issues detected |
| 2 | Error - Connection error, timeout, or invalid input |

## Accuracy Comparison

| Method | Accuracy | Requirements |
|--------|----------|--------------|
| SSH + WP-CLI | 100% | SSH access, WP-CLI installed |
| WP-CLI stdin | 100% | Server access, WP-CLI installed |
| Remote | 60-85% | URL only |

## CPE Format

WordPress core:
```
cpe:2.3:a:wordpress:wordpress:VERSION:*:*:*:*:*:*:*
```

Plugins/Themes:
```
cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:wordpress:*:*
```

For vulnerability correlation:
```bash
wpvet detect https://example.com -f cpe | grep -f - cve-database.txt
```

## Part of xxVet Series

xxVet is a collection of 15 focused security CLI tools. See [full catalog](https://www.notion.so/xxVet-CLI-304b1e6bcbc2817abe62d4aecee9914a).

## License

MIT
