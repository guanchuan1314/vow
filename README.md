# Vow - AI Output Verification Engine

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

📖 [llms.txt](./llms.txt) — AI-friendly documentation

Vow is a local-first AI output verification engine that analyzes code and text to detect patterns indicative of AI generation, security vulnerabilities, and potential hallucinations.

## Features

### 🔍 **Multi-Language Code Analysis**
- **16 Programming Languages**: Python, JavaScript, TypeScript, Java, Go, Ruby, C, C++, C#, PHP, Swift, Kotlin, R, Scala, Perl, Lua, Dart, Haskell, and MQL5
- **Hallucinated API Detection**: Validates imports against known package databases (PyPI, npm, Maven Central, Go modules, RubyGems, and more)
- **Security Pattern Detection**: Finds dangerous functions, hardcoded secrets, and vulnerabilities across all supported languages
- **Line-precise reporting**: Pinpoints exact locations of issues

### 📝 **AI-Generated Text Detection**
- **Linguistic Pattern Analysis**: Detects AI-favored phrases and word choices
- **Writing Style Analysis**: Identifies formal transitions overused by AI
- **Source Citation Validation**: Flags confident claims without apparent citations
- **Markdown & Plain Text Support**

### 🛡️ **Prompt Injection & Secret Exfiltration Detection**
- **Prompt Injection Defense**: Detects attempts to manipulate AI systems via hidden instructions
- **Secret Exfiltration Prevention**: Identifies code that steals API keys, passwords, and sensitive files
- **Backdoor Detection**: Finds reverse shells, cron injection, and SSH key manipulation
- **Data Exfiltration Analysis**: Catches suspicious HTTP requests and DNS tunneling patterns
- **Base64 Decode Analysis**: Examines encoded content for hidden malicious instructions
- **Multi-Language Support**: All 16 supported programming languages including Python, JavaScript, TypeScript, Java, Go, Ruby, C, C++, C#, PHP, Swift, Kotlin, R, Scala, Perl, Lua, Dart, Haskell, MQL5, Rust, and Shell scripts

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

### 🌐 **Port Scanning & Security Analysis**
- **Fast Concurrent Scanning**: Configurable concurrency for efficient port scanning
- **Security Evaluation**: Each open port evaluated against security baselines
- **Risk Assessment**: Ports classified by risk level (Critical, High, Medium, Low)
- **Comprehensive Reporting**: Detailed security recommendations for each service
- **Network Support**: IP addresses, hostnames, and CIDR ranges

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

# Port scanning and security analysis
vow scan 192.168.1.1 --ports 22,80,443
vow scan example.com --ports 1-1000 --issues-only

# Advanced usage examples
vow check . --verbose --max-file-size 5 --max-depth 3
vow check large-project/ --quiet --ci --threshold 90
vow check . --format json --max-issues 10 > analysis.json
```

### Practical Examples

#### CI/CD Pipeline Integration
```bash
# GitHub Actions / GitLab CI
vow check . --ci --threshold 80 --quiet
echo "Exit code: $?"  # 0 = pass, 1 = fail

# Save structured results
vow check . --format json > vow-results.json
vow check . --format sarif > vow-results.sarif

# Quick security scan of changed files
git diff --name-only | grep -E '\.(py|js|ts)$' | xargs vow check --ci
```

#### Large Codebase Analysis
```bash
# Skip large files and limit depth for performance
vow check /large/codebase --max-file-size 2 --max-depth 5 --quiet

# Get detailed timing for performance optimization  
vow check src/ --verbose --max-issues 5

# Focus on high-priority files only
vow check . --quiet | grep -E "(CRITICAL|HIGH)"
```

#### Development Workflow
```bash
# Quick check before commit
vow check $(git diff --cached --name-only)

# Analyze AI-generated code
vow check ai-generated.py --verbose --threshold 90

# Monitor specific directories with custom rules
vow check src/ --rules .vow/custom-rules --threshold 85
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

### JSON Output (Enhanced for CI/CD)
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
        },
        {
          "severity": "High",
          "message": "Potentially dangerous eval() usage detected",
          "line": 21,
          "rule": "eval_usage"
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
    },
    "files_per_second": 45.2,
    "total_time_seconds": 1.3,
    "files_skipped": 2,
    "skipped_reasons": {
      "too_large": 1,
      "metadata_error": 1
    }
  }
}
```

Perfect for parsing in CI/CD pipelines:
```bash
# Extract trust score for threshold checking
jq '.summary.avg_score' vow-results.json

# Count critical issues
jq '.summary.issues_by_severity.critical // 0' vow-results.json

# List all files with issues
jq -r '.files[] | select(.issues | length > 0) | .path' vow-results.json

# Performance monitoring
jq '.summary.files_per_second' vow-results.json
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

- **Code**: 
  - Python: `.py`
  - JavaScript: `.js`, `.jsx`
  - TypeScript: `.ts`, `.tsx`
  - Java: `.java`
  - Go: `.go`
  - Ruby: `.rb`
  - C: `.c`, `.h`
  - C++: `.cpp`, `.cc`, `.cxx`, `.hpp`
  - C#: `.cs`
  - PHP: `.php`
  - Swift: `.swift`
  - Kotlin: `.kt`, `.kts`
  - R: `.r`
  - Scala: `.scala`
  - Perl: `.pl`, `.pm`
  - Lua: `.lua`
  - Dart: `.dart`
  - Haskell: `.hs`
  - MQL5: `.mq5`, `.mqh`
  - Rust: `.rs`
  - Shell: `.sh`, `.bash`, `.zsh`
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

```bash
vow init [PATH]                 Initialize Vow project
vow check <PATH|-> [OPTIONS]    Analyze files or stdin
vow scan <TARGET> [OPTIONS]     Scan network ports for security issues

Check Options:
  -f, --format <FORMAT>         Output format: terminal, json, sarif
  -r, --rules <PATH>           Custom rules directory
      --threshold <SCORE>       Minimum trust score (0-100)
      --ci                     CI mode (JSON output, exit on failure)
  -v, --verbose                Verbose output with per-analyzer timing
  -q, --quiet                  Quiet output (errors and summary only)
      --max-file-size <MB>     Maximum file size to process in MB (default: 10)
      --max-depth <N>          Maximum directory depth to scan (default: 20)
      --max-issues <N>         Maximum issues per file before moving on (default: 100)

Scan Options:
  -p, --ports <PORTS>          Port range (e.g., 1-1000, 22,80,443)
  -f, --format <FORMAT>        Output format: terminal, json
      --timeout <MS>           Connection timeout in milliseconds
  -c, --concurrency <NUM>      Number of concurrent scans
      --issues-only           Only show security issues
```

## Advanced Features

### 🗂️ **File Filtering (.vowignore)**

Create a `.vowignore` file (gitignore syntax) to exclude files/directories:

```gitignore
# Ignore test files
**/test/**
**/tests/**
**/__tests__/**
*.test.js
*.test.ts

# Ignore build artifacts
dist/
build/
target/
node_modules/

# Ignore temporary files
*.tmp
*.temp
.cache/
```

### 📊 **JSON Output for CI/CD**

Perfect for automated pipelines and integration with other tools:

```bash
# Basic JSON output
vow check src/ --format json

# CI mode (JSON + proper exit codes)
vow check . --ci --threshold 80

# Save results for further processing
vow check . --format json > results.json
```

### 🐞 **Verbose Mode with Performance Insights**

Get detailed timing breakdown per analyzer per file:

```bash
vow check suspicious.py --verbose
```

Output includes:
```
🔍 Analyzing suspicious.py (Python)
  📊 Code Analyzer: 12.34ms (3 issues)
  🛡️  Injection Analyzer: 8.76ms (1 issue)
  ⏱️  Total analysis time: 21.45ms (Trust Score: 45%)
```

### ⚡ **Performance & Scale Controls**

Optimize for large codebases:

```bash
# Skip large files (default: 10MB)
vow check . --max-file-size 5

# Limit directory depth (default: 20)
vow check . --max-depth 10

# Control issue reporting per file (default: 100)
vow check . --max-issues 50

# Quiet mode for CI (only shows summary)
vow check . --quiet --ci
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