# Vow - AI Output Verification Engine

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Vow is a local-first AI output verification engine that analyzes code and text to detect patterns indicative of AI generation, security vulnerabilities, and potential hallucinations.

## Features

### 🔍 **Multi-Language Code Analysis**
- **Python & JavaScript/TypeScript**: Comprehensive security scanning
- **Hallucinated API Detection**: Validates imports against known package databases
- **Security Pattern Detection**: Finds dangerous functions, hardcoded secrets, and vulnerabilities
- **Line-precise reporting**: Pinpoints exact locations of issues

### 📝 **AI-Generated Text Detection**
- **Linguistic Pattern Analysis**: Detects AI-favored phrases and word choices
- **Writing Style Analysis**: Identifies formal transitions overused by AI
- **Source Citation Validation**: Flags confident claims without apparent citations
- **Markdown & Plain Text Support**

### ⚙️ **Flexible Rule System**
- **YAML-Based Rules**: Define custom detection patterns
- **Multiple Pattern Types**: Contains, regex, starts_with, ends_with
- **File Type Filtering**: Apply rules to specific file extensions
- **Severity Levels**: Critical, High, Medium, Low

### 📊 **Multiple Output Formats**
- **Terminal**: Colorized, human-readable reports
- **JSON**: Machine-readable for integration
- **SARIF 2.1.0**: GitHub/GitLab code scanning integration

### 🔧 **CI/CD Integration**
- **Exit Code Support**: Non-zero exit for failures
- **Threshold Configuration**: Set minimum trust scores
- **Pipe Support**: Read from stdin for shell pipelines

## Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/guanchuan1314/vow.git
cd vow
cargo build --release
```

### Initialize a Project

```bash
# Create .vow/ directory with default config and rules
vow init
```

### Basic Usage

```bash
# Analyze a single file
vow check suspicious_code.py

# Analyze a directory
vow check src/

# Read from stdin
echo "print('Hello AI world')" | vow check -

# Set trust score threshold
vow check code.py --threshold 80

# JSON output for CI
vow check . --ci
```

## Example Output

### Terminal Report
```
Vow Analysis Report
==================================================

Summary
  Files analyzed: 1
  Average trust score: 25%
  Total issues: 8

Issues by Severity
  CRITICAL: 2
  HIGH: 3
  MEDIUM: 3

File Details

suspicious_code.py (25%)
  🚨 CRITICAL Hardcoded API key or secret detected (line 12)
  ⚠️  HIGH Potentially dangerous eval() usage detected (line 21)
  ℹ️  MEDIUM Potentially hallucinated package import: 'unknown_package' (line 7)
  ⚠️  HIGH Shell injection risk - subprocess with shell=True (line 17)
  🚨 CRITICAL Dangerous rm -rf command detected (line 16)

Overall Verdict
❌ Code has significant signs of AI generation or security issues
```

### JSON Output
```json
{
  "files": [
    {
      "path": "suspicious_code.py",
      "file_type": "Python",
      "issues": [
        {
          "severity": "Critical",
          "message": "Hardcoded API key or secret detected",
          "line": 12,
          "rule": "api_keys"
        }
      ],
      "trust_score": 25
    }
  ],
  "summary": {
    "total_files": 1,
    "avg_score": 25,
    "total_issues": 8,
    "issues_by_severity": {
      "critical": 2,
      "high": 3,
      "medium": 3
    }
  }
}
```

## Configuration

### Project Config (`.vow/config.yaml`)
```yaml
threshold: 70
enabled_analyzers:
  - code
  - text
  - rules
custom_rule_dirs:
  - ./custom-rules
```

### Custom Rules (`.vow/rules/security.yaml`)
```yaml
name: "hardcoded_passwords"
description: "Detect hardcoded passwords in code"
severity: "high"
patterns:
  - type: "regex"
    pattern: 'password\s*=\s*["\'][^"\']+["\']'
  - type: "contains"
    pattern: "SECRET_KEY = "
file_types: ["py", "js", "ts"]
```

## Supported File Types

- **Code**: `.py`, `.js`, `.jsx`, `.ts`, `.tsx`
- **Text**: `.md`, `.txt`
- **Config**: `.yaml`, `.yml`, `.json`

## Detection Capabilities

### Code Analysis
- **Security Vulnerabilities**: eval(), exec(), system calls, SQL injection
- **Dangerous Operations**: rm -rf, chmod 777, SSL verification bypass
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Hallucinated Imports**: Unknown packages not in PyPI/npm top lists

### Text Analysis
- **AI Identity Markers**: "As an AI", "I cannot"
- **AI-Favored Language**: "delve", "comprehensive", "multifaceted"
- **Formal Transitions**: Overuse of "furthermore", "moreover", "additionally"
- **Unsourced Claims**: Confident statements without citations

## Trust Score Algorithm

Trust scores start at 100% and decrease based on issue severity:
- **Critical Issues**: -25 points each
- **High Issues**: -15 points each  
- **Medium Issues**: -8 points each
- **Low Issues**: -3 points each

Minimum score: 0%, Maximum score: 100%

## CI Integration

### GitHub Actions
```yaml
- name: AI Code Analysis
  run: |
    vow check . --ci --threshold 70 > vow-results.json
    vow check . --format sarif > vow.sarif
```

### Exit Codes
- `0`: Analysis passed (score ≥ threshold)
- `1`: Analysis failed (score < threshold or errors)

## Command Line Reference

```
vow init [PATH]                 Initialize Vow project
vow check <PATH|-> [OPTIONS]    Analyze files or stdin

Options:
  -f, --format <FORMAT>         Output format: terminal, json, sarif
  -r, --rules <PATH>           Custom rules directory
      --threshold <SCORE>       Minimum trust score (0-100)
      --ci                     CI mode (JSON output, exit on failure)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `cargo test` and `cargo clippy`
5. Submit a pull request

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Roadmap

- [ ] Machine learning models for advanced AI detection
- [ ] Plugin system for custom analyzers
- [ ] Web UI for result visualization
- [ ] Integration with popular IDEs
- [ ] Support for more programming languages

---

**Vow**: Because trust should be verified, not assumed.