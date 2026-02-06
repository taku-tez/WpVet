# WpVet

WordPress plugin/theme security scanner with CPE output for vulnerability correlation.

## Features

- **WP-CLI Integration**: 100% accuracy by parsing `wp plugin list --format=json`
- **Remote Detection**: Scan WordPress sites without server access (60-85% accuracy)
- **CPE Output**: Standard format for vulnerability database correlation
- **Multiple Output Formats**: CPE, JSON, table

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

# CPE output
wpvet scan ssh://user@host/path --format cpe
```

### WP-CLI Integration (Recommended)

On your WordPress server:

```bash
# Scan plugins
wp plugin list --format=json | wpvet detect --stdin --format cpe

# Output:
# cpe:2.3:a:developer:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*
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

# CPE output only
wpvet detect https://example.com --format cpe

# JSON output
wpvet detect https://example.com --format json
```

## Output Formats

### CPE Format
```
cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*
cpe:2.3:a:contact-form-7:contact-form-7:5.7.1:*:*:*:*:wordpress:*:*
```

### Table Format (default)
```
Target: https://example.com
Scan time: 2024-01-15T10:30:00.000Z
Source: remote

WordPress Core:
  Version: 6.4.2 (confidence: 90%)
  CPE: cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*

Plugins:
  Name                           Version      Status     Confidence
  ------------------------------ ------------ ---------- ----------
  contact-form-7                 5.7.1        -          85%
  elementor                      3.18.0       -          85%

Total: 3 component(s) detected
```

## Accuracy Comparison

| Method | Accuracy | Requirements |
|--------|----------|--------------|
| WP-CLI | 100% | Server access, WP-CLI installed |
| Remote | 60-85% | URL only |
| Local files | 95% | File system access |

## License

MIT
