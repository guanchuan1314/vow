# Introduction

Welcome to **Vow**, a local-first AI output verification engine that helps you detect hallucinations, security issues, and quality problems in AI-generated code and text.

## What is Vow?

Vow is a command-line tool that analyzes files, directories, or stdin input to identify potential issues in AI-generated content. It uses a combination of:

- **Static code analysis** to detect hallucinated APIs and imports
- **Text analysis** to identify potential fabricated information  
- **Security scanning** to catch dangerous patterns
- **Custom rule engine** for domain-specific checks
- **Machine learning models** running locally via ONNX

## Key Features

- **🔒 Privacy-first**: All analysis runs locally - no data leaves your machine
- **⚡ Fast**: Single binary, no dependencies, sub-second analysis
- **🎯 Accurate**: Specialized models trained on AI hallucination patterns  
- **🔧 Extensible**: YAML-based rules and WASM plugin system
- **🏗️ CI-ready**: JSON, SARIF, and HTML output formats
- **📊 Trust scoring**: Quantified confidence in AI outputs

## Use Cases

### Software Development
- Validate AI-generated code before committing
- Check for hallucinated function calls or imports
- Detect security vulnerabilities in generated code
- Integrate into CI/CD pipelines for automated quality gates

### Content Creation
- Verify factual accuracy in AI-written documentation
- Check for fabricated references or citations
- Validate technical explanations and tutorials

### Code Review
- Augment human code review with automated AI output verification
- Flag potentially problematic AI-generated sections
- Provide trust scores to guide review priorities

## How It Works

Vow uses a multi-stage analysis pipeline:

1. **Input Processing**: Reads files, directories, or stdin
2. **Content Detection**: Identifies likely AI-generated sections
3. **Multi-analyzer Pipeline**: 
   - Code analyzer for syntax and API validation
   - Text analyzer for factual consistency
   - Security scanner for dangerous patterns
4. **Rule Engine**: Applies custom YAML rules
5. **Trust Scoring**: Calculates confidence metrics
6. **Output**: Results in JSON, SARIF, or HTML formats

## Getting Started

Ready to start using Vow? Head over to the [Installation](getting-started/installation.md) guide to get up and running in minutes.

For a quick overview of basic usage, check out the [Quick Start](getting-started/quick-start.md) guide.
