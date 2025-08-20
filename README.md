# Confuc - Advanced Dependency Confusion Scanner for Burp Suite

**Confuc** is a Burp Suite extension for detecting dependency confusion vulnerabilities by scanning HTTP responses for exposed dependency files and references.

## Features

- Passive and real-time scanning of HTTP traffic for package manifests and JS files
- Detects references to private dependencies and checks public registries (npm)
- Reports findings as Burp Suite issues
- Extensible via config file and pluggable parsers

## Usage

1. Install via Burp Suite Extender (Jython required)
2. Extension auto-scans HTTP traffic and highlights risks in its Suite tab
3. Findings are shown in the table and reported as issues

## Building & Testing

- Extension files:
  - `DependencyConfusionScanner.py` (main extension)
  - `parsers.py` (dependency file parsers)
  - `registry.py` (registry checker)
  - `config.py` (config loader)
- Unit tests in `tests/`

## Configuration

Edit `confusion_config.json` to customize file types and enable/disable registry checks.

## License

MIT
