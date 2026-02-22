# Vow 🛡️

> A local-first AI output verification engine

Vow is a command-line tool designed to verify and analyze AI-generated outputs, source code, and text content for security vulnerabilities, hallucinations, and quality issues. Built with Rust for performance and reliability, Vow runs entirely on your local machine without sending your code to external services.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org)

## 🚀 Features

- **Local-First**: No external API calls - everything runs on your machine
- **Multi-Format Analysis**: Supports Python, JavaScript/TypeScript, Rust, Markdown, and more
- **Configurable Rules**: YAML-based rule engine for custom verification patterns
- **Multiple Output Formats**: Terminal (pretty), JSON, and SARIF support
- **Security Focus**: Detects dangerous patterns, hardcoded secrets, and injection risks
- **AI Hallucination Detection**: Identifies AI-generated content markers and limitations
- **Fast & Lightweight**: Single binary, optimized for CI/CD integration

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/guanchuan1314/vow.git
cd vow

# Build with Cargo
cargo build --release

# Install globally
cargo install --path .
```

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/guanchuan1314/vow/releases).

## 🔧 Usage

### Basic Usage

```bash
# Check a single file
vow check example.py

# Check a directory
vow check src/

# Specify custom rules
vow check --rules .sentinel/rules/ src/

# Output as JSON
vow check --format json example.py

# Output as SARIF (for CI integration)
vow check --format sarif src/ > results.sarif
```

### Example Output

```
╭─────────────────────────────────────────────╮
│ Vow Verification Report                     │
├─────────────────────────────────────────────┤
│ File: example.py                            │
│ Trust Score: 85%                            │
├─────────────────────────────────────────────┤
│ Verification Checks:                        │
│ ✓ Syntax Check               PASS          │
│ ✓ Security Scan              PASS          │
│ ✗ API Validation             FAIL          │
├─────────────────────────────────────────────┤
│ Total: 3  Passed: 2  Failed: 1             │
╰─────────────────────────────────────────────╯

⚠️ Some issues found, but overall score is acceptable.
```

## ⚙️ Configuration

### Rule Files

Vow uses YAML-based rule files for configurable verification. Create rules in `.sentinel/rules/`:

```yaml
# .sentinel/rules/security.yaml
- id: dangerous-eval
  name: Dangerous eval() Usage
  description: Detects potentially dangerous eval() function calls
  severity: high
  file_types:
    - py
    - js
  patterns:
    - pattern_type: contains
      value: "eval("
      message: "Use of eval() detected - this can lead to code injection vulnerabilities"
```

### Supported Pattern Types

- `contains`: Check if content contains a string
- `starts_with`: Check if content starts with a string  
- `ends_with`: Check if content ends with a string
- `regex`: Regular expression matching (coming soon)

## 🏗️ Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│    Input    │───▶│   Analyzers  │───▶│    Rules    │
│ Files/Stdin │    │ Code │ Text  │    │   Engine    │
└─────────────┘    └──────────────┘    └─────────────┘
                           │                    │
                           ▼                    ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Output    │◀───│   Reporting  │◀───│   Results   │
│JSON│SARIF   │    │ Terminal│CI │    │ Aggregation │
└─────────────┘    └──────────────┘    └─────────────┘
```

### Core Components

- **CLI**: Command-line interface built with `clap`
- **Analyzers**: Pluggable analyzers for different content types
  - Code Analyzer: Language-specific pattern detection
  - Text Analyzer: Natural language analysis for AI markers
- **Rules Engine**: YAML-based configurable rule system
- **Reporting**: Multiple output formats for different use cases

## 🚧 Roadmap

### Phase 1 (Current)
- [x] Basic CLI scaffold
- [x] Code and text analyzers (stubs)
- [x] YAML rule engine
- [x] Terminal and JSON output
- [ ] SARIF output implementation
- [ ] Regex pattern support

### Phase 2 (Next)
- [ ] ONNX Runtime integration for ML models
- [ ] Advanced hallucination detection
- [ ] WASM plugin system
- [ ] HTML report generation
- [ ] GitHub Actions integration

### Phase 3 (Future)
- [ ] Web UI dashboard
- [ ] Real-time monitoring
- [ ] Custom model training
- [ ] Enterprise integrations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/guanchuan1314/vow.git
cd vow

# Install dependencies
cargo build

# Run tests
cargo test

# Run with sample file
cargo run -- check .sentinel/rules/security.yaml
```

### Code Standards

- Follow Rust community standards (`rustfmt`, `clippy`)
- Add tests for new features
- Update documentation for API changes
- Ensure CI passes before submitting PRs

## 📄 License

This project is dual-licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) and [clap](https://clap.rs/)
- Inspired by static analysis tools like ESLint, Clippy, and security scanners
- SARIF standard compliance for CI/CD integration

---

**Website**: [getvow.dev](https://getvow.dev) | **Issues**: [GitHub Issues](https://github.com/guanchuan1314/vow/issues) | **Discussions**: [GitHub Discussions](https://github.com/guanchuan1314/vow/discussions)