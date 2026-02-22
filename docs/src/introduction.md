# Introduction

<div class="hero-section">
  <h1 class="hero-title">Vow</h1>
  <p class="hero-tagline">Trust, verified. Locally.</p>
  <p style="font-size: 1.1rem; color: var(--text-primary); max-width: 600px; margin: 0 auto;">
    A local-first AI output verification engine that helps you detect hallucinations, security issues, and quality problems in AI-generated code and text.
  </p>
</div>

## What is Vow?

Vow is a command-line tool that analyzes files, directories, or stdin input to identify potential issues in AI-generated content. It uses a combination of advanced analysis techniques to ensure the reliability and security of AI outputs.

<div class="feature-grid">
  <div class="feature-card">
    <h3>🔒 Privacy-First</h3>
    <p>All analysis runs locally - no data leaves your machine. Your code and content stay completely private.</p>
  </div>
  
  <div class="feature-card">
    <h3>⚡ Lightning Fast</h3>
    <p>Single binary, no dependencies, sub-second analysis. Optimized for real-world development workflows.</p>
  </div>
  
  <div class="feature-card">
    <h3>🎯 Accurate Detection</h3>
    <p>Specialized models trained on AI hallucination patterns with high precision and low false positives.</p>
  </div>
  
  <div class="feature-card">
    <h3>🔧 Extensible</h3>
    <p>YAML-based rules and WASM plugin system for custom domain-specific checks.</p>
  </div>
  
  <div class="feature-card">
    <h3>🏗️ CI/CD Ready</h3>
    <p>JSON, SARIF, and HTML output formats with seamless CI integration.</p>
  </div>
  
  <div class="feature-card">
    <h3>📊 Trust Scoring</h3>
    <p>Quantified confidence metrics to guide decision-making and review priorities.</p>
  </div>
</div>

## How It Works

Vow uses a sophisticated multi-stage analysis pipeline:

1. **Input Processing**: Reads files, directories, or stdin with intelligent content detection
2. **AI Content Detection**: Identifies likely AI-generated sections using advanced heuristics
3. **Multi-Analyzer Pipeline**: 
   - **Code analyzer** for syntax and API validation
   - **Text analyzer** for factual consistency and hallucination detection
   - **Security scanner** for dangerous patterns and vulnerabilities
4. **Rule Engine**: Applies custom YAML rules for domain-specific requirements
5. **Trust Scoring**: Calculates confidence metrics using multiple signals
6. **Output**: Structured results in JSON, SARIF, or HTML formats

## Use Cases

### 🔍 Software Development
- Validate AI-generated code before committing to version control
- Check for hallucinated function calls, imports, or API endpoints
- Detect security vulnerabilities in generated code
- Integrate into CI/CD pipelines for automated quality gates

### 📝 Content Creation
- Verify factual accuracy in AI-written documentation
- Check for fabricated references, citations, or sources
- Validate technical explanations and tutorials for correctness

### 👥 Code Review
- Augment human code review with automated AI output verification
- Flag potentially problematic AI-generated sections
- Provide trust scores to guide review priorities and focus areas

<div class="install-section">
  <h3>Quick Install</h3>
  <p>Get started with Vow in seconds:</p>
  <pre><code>curl -sSL https://getvow.dev/install.sh | sh</code></pre>
  <a href="getting-started/installation.html" class="cta-button">Get Started</a>
</div>

## Core Features

### 🧠 **Advanced Analysis**
- **Static code analysis** to detect hallucinated APIs and imports
- **Text analysis** to identify potential fabricated information  
- **Security scanning** to catch dangerous patterns
- **Custom rule engine** for domain-specific checks
- **Machine learning models** running locally via ONNX

### 🛡️ **Security & Privacy**
- **100% local processing** - no cloud dependencies
- **Open source** with transparent algorithms
- **Minimal attack surface** with single binary distribution
- **No telemetry** or data collection

### 🚀 **Developer Experience**
- **Zero configuration** to get started
- **Comprehensive documentation** and examples
- **Multiple output formats** for different workflows
- **Extensive CLI options** for fine-tuning

---

**Ready to verify your AI outputs?** Head over to the [Installation Guide](getting-started/installation.md) to get up and running in minutes, or check out the [Quick Start](getting-started/quick-start.md) for a rapid overview of basic usage.