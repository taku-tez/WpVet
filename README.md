# WpVet v0.3.0

WordPress plugin/theme security scanner with CPE output for vulnerability correlation.

## Features

- **WP-CLI Integration**: 100% accuracy by parsing `wp plugin list --format=json`
- **Remote Detection**: Scan WordPress sites without server access (60-85% accuracy)
- **SSH Scanning**: Direct scanning via SSH + WP-CLI
- **CPE Output**: Standard format for vulnerability database correlation
- **Multiple Output Formats**: CPE, JSON, table
- **Configurable**: Custom plugin/theme lists via config file
- **Concurrent Scanning**: Configurable concurrency with retry support

## Installation

```bash
npm install -g wpvet
```

## Usage

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

Total: 3 component(s) detected
```

### JSON Output Schema

```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source": "remote",
  "site": {
    "site_url": "https://example.com",
    "home_url": "https://example.com",
    "multisite": false
  },
  "core": {
    "type": "core",
    "slug": "wordpress",
    "name": "WordPress",
    "version": "6.4.2",
    "cpe": "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
    "confidence": 95,
    "source": "remote"
  },
  "plugins": [
    {
      "type": "plugin",
      "slug": "contact-form-7",
      "name": "Contact Form 7",
      "version": "5.7.1",
      "status": "active",
      "update": "none",
      "auto_update": "on",
      "cpe": "cpe:2.3:a:rocklobster:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*",
      "confidence": 100,
      "source": "wp-cli"
    }
  ],
  "themes": [],
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

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - WordPress detected with components |
| 1 | No detection - WordPress not found or no components |
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

## License

MIT
