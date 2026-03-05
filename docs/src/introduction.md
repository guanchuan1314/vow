# Introduction

<div class="hero-section">
  <h1 class="hero-title">Vow</h1>
  <p class="hero-tagline">Trust, verified. Locally.</p>
  <p style="font-size: 1.1rem; color: var(--text-primary); max-width: 600px; margin: 0 auto;">
    A local-first AI output verification engine that helps you detect hallucinations, security issues, and quality problems in AI-generated code and text.
  </p>
</div>

## What is Vow?

Vow is a high-performance command-line tool that analyzes files, directories, or stdin input to identify potential issues in AI-generated content. It uses a combination of advanced analysis techniques to ensure the reliability and security of AI outputs across **20+ programming languages**.

<div class="feature-grid">
  <div class="feature-card">
    <h3>🔒 Privacy-First</h3>
    <p>All analysis runs locally - no data leaves your machine. Your code and content stay completely private.</p>
  </div>
  
  <div class="feature-card">
    <h3>⚡ Lightning Fast</h3>
    <p>Parallel processing engine analyzing 35+ files/sec with optimized HashSet lookups and smart file filtering.</p>
  </div>
  
  <div class="feature-card">
    <h3>🎯 Accurate Detection</h3>
    <p>Advanced heuristics with improved false positive handling and precision-tuned detection algorithms.</p>
  </div>
  
  <div class="feature-card">
    <h3>🔧 Extensible</h3>
    <p>YAML-based rules system with .vowignore support for project-specific customization.</p>
  </div>
  
  <div class="feature-card">
    <h3>🏗️ CI/CD Ready</h3>
    <p>JSON, SARIF, and HTML output formats with detailed performance summaries for automated workflows.</p>
  </div>
  
  <div class="feature-card">
    <h3>📊 Trust Scoring</h3>
    <p>Quantified confidence metrics to guide decision-making and review priorities.</p>
  </div>
</div>

## How It Works

Vow uses a sophisticated multi-stage analysis pipeline with parallel processing:

1. **Input Processing**: Intelligently reads files, directories, or stdin with .vowignore filtering support
2. **AI Content Detection**: Identifies likely AI-generated sections using advanced heuristics across 20+ languages
3. **Multi-Analyzer Pipeline**: 
   - **Code analyzer** for syntax, API validation, and import verification
   - **Text analyzer** for factual consistency and hallucination detection
   - **Security scanner** for dangerous patterns and vulnerabilities
4. **Rule Engine**: Applies custom YAML rules for domain-specific requirements
5. **Trust Scoring**: Calculates confidence metrics using multiple signals and improved false positive handling
6. **Performance Summary**: Provides detailed timing and processing statistics
7. **Output**: Structured results in JSON, SARIF, table, or HTML formats

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
- **Multi-language support**: Python, JavaScript, TypeScript, Java, Go, Ruby, C, C++, C#, PHP, Swift, Kotlin, R, Scala, Perl, Lua, Dart, Haskell, MQL5, Rust, Shell
- **Static code analysis** to detect hallucinated APIs and imports
- **Text analysis** to identify potential fabricated information  
- **Security scanning** to catch dangerous patterns
- **Custom rule engine** for domain-specific checks
- **Improved false positive handling** with precision-tuned algorithms

### ⚡ **High Performance**
- **Parallel processing** with rayon for optimal CPU utilization
- **35+ files per second** analysis speed on typical hardware
- **Optimized data structures** with HashSet lookups for fast package verification
- **Smart filtering** with .vowignore support to skip unnecessary files
- **Configurable limits** for file size, directory depth, and issue count

### 🛡️ **Security & Privacy**
- **100% local processing** - no cloud dependencies
- **Open source** with transparent algorithms
- **Minimal attack surface** with single binary distribution
- **No telemetry** or data collection

### 🚀 **Developer Experience**
- **Zero configuration** to get started
- **Flexible CLI options**: `--quiet`, `--verbose`, `--max-file-size`, `--max-depth`, `--max-issues`
- **Multiple output formats**: JSON, SARIF, table, HTML with performance summaries
- **CI/CD integration** with structured JSON output for automated workflows
- **Comprehensive documentation** and examples

---

**Ready to verify your AI outputs?** Head over to the [Installation Guide](getting-started/installation.md) to get up and running in minutes, or check out the [Quick Start](getting-started/quick-start.md) for a rapid overview of basic usage.