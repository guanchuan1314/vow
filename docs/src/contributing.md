# Contributing to Vow

Thank you for your interest in contributing to Vow! This guide will help you get started with contributing code, documentation, or ideas to make Vow better for everyone.

## Ways to Contribute

### 🐛 Bug Reports
Found a bug? Please check existing issues first, then create a new issue with:
- Steps to reproduce the problem
- Expected vs. actual behavior  
- Your environment (OS, Vow version, etc.)
- Sample code/files that trigger the issue

### 💡 Feature Requests
Have an idea for a new feature? Open an issue with:
- Clear description of the use case
- Why existing features don't solve the problem
- Proposed solution or API design
- Examples of how it would be used

### 📝 Documentation
Help improve our docs by:
- Fixing typos or unclear explanations
- Adding examples and use cases
- Translating docs to other languages
- Creating tutorials and guides

### 🔧 Code Contributions
Contribute code improvements:
- Bug fixes
- New analyzers or rules
- Performance improvements
- New output formats
- Test coverage improvements

## Development Setup

### Prerequisites
- Rust 1.70+ ([rustup.rs](https://rustup.rs/))
- Git
- Python 3.8+ (for integration tests)
- Node.js 16+ (for JavaScript analyzer tests)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/guanchuan1314/vow.git
cd vow

# Build in development mode
cargo build

# Run tests
cargo test

# Build documentation
mdbook build docs/

# Run integration tests
python test/run_integration_tests.py
```

### Development Workflow

1. **Fork the repository** on GitHub
2. **Create a feature branch**: `git checkout -b feature/my-new-feature`
3. **Make your changes** with tests and documentation
4. **Run the test suite**: `cargo test && python test/run_integration_tests.py`
5. **Commit your changes**: Use conventional commits format
6. **Push to your fork**: `git push origin feature/my-new-feature`
7. **Create a Pull Request** on GitHub

## Code Style and Standards

### Rust Code Style

We use `rustfmt` and `clippy` for consistent code style:

```bash
# Format code
cargo fmt

# Check for common issues
cargo clippy -- -D warnings

# Run both as pre-commit check
cargo fmt --check && cargo clippy -- -D warnings
```

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(analyzer): add hallucination detection for Go imports
fix(cli): handle empty files without panicking
docs(readme): add installation instructions for Windows
test(integration): add tests for SARIF output format
```

Types:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `ci`: CI/CD changes

## Project Structure

```
vow/
├── src/
│   ├── analyzers/          # Core analysis logic
│   │   ├── code/          # Code analyzer
│   │   ├── text/          # Text analyzer
│   │   └── security/      # Security analyzer
│   ├── cli/               # Command-line interface
│   ├── config/            # Configuration handling
│   ├── models/            # ML model interfaces
│   ├── rules/             # Rule engine
│   └── output/            # Output formatters
├── test/
│   ├── fixtures/          # Test files
│   ├── integration/       # Integration tests
│   └── unit/             # Unit tests
├── models/               # Pre-trained model files
├── docs/                 # Documentation source
└── scripts/             # Build and release scripts
```

## Writing Analyzers

### Analyzer Interface

All analyzers implement the `Analyzer` trait:

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn analyze(&self, content: &AnalysisInput) -> Result<AnalysisResult>;
    fn supported_languages(&self) -> &[Language];
}
```

### Example Analyzer

```rust
use crate::analyzer::{Analyzer, AnalysisInput, AnalysisResult, Issue};

pub struct MyAnalyzer {
    // Analyzer state/configuration
}

impl Analyzer for MyAnalyzer {
    fn name(&self) -> &str {
        "my-analyzer"
    }
    
    fn analyze(&self, input: &AnalysisInput) -> Result<AnalysisResult> {
        let mut issues = Vec::new();
        
        // Your analysis logic here
        if self.detect_issue(&input.content) {
            issues.push(Issue {
                rule: "my-rule".to_string(),
                message: "Issue detected".to_string(),
                severity: Severity::Medium,
                line: 1,
                column: 0,
            });
        }
        
        Ok(AnalysisResult {
            trust_score: 0.8,
            issues,
        })
    }
    
    fn supported_languages(&self) -> &[Language] {
        &[Language::Python, Language::JavaScript]
    }
}
```

### Testing Analyzers

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_analyzer_detects_issue() {
        let analyzer = MyAnalyzer::new();
        let input = AnalysisInput {
            content: "problematic code here".to_string(),
            language: Language::Python,
            file_path: "test.py".into(),
        };
        
        let result = analyzer.analyze(&input).unwrap();
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].rule, "my-rule");
    }
}
```

## Writing Rules

### Rule Format

Rules are written in YAML format:

```yaml
# rules/my-rules.yaml
name: "My Custom Rules"
version: "1.0.0"
description: "Custom rules for my project"

rules:
  - id: "custom-pattern"
    name: "Detect Custom Pattern"
    description: "Detects usage of custom problematic pattern"
    severity: "medium"
    
    # Pattern matching
    patterns:
      - regex: "forbidden_function\\("
        message: "forbidden_function() should not be used"
      
    # Language-specific patterns
    languages:
      python:
        - regex: "import suspicious_module"
          message: "suspicious_module is not allowed"
      
    # Context-aware rules
    contexts:
      - type: "function"
        patterns:
          - regex: "eval\\("
            message: "eval() in functions is dangerous"
```

### Testing Rules

```bash
# Test rules against sample code
vow rules test rules/my-rules.yaml test/fixtures/sample.py

# Validate rule syntax
vow rules validate rules/my-rules.yaml
```

## Adding Output Formats

### Output Format Interface

```rust
pub trait OutputFormatter: Send + Sync {
    fn name(&self) -> &str;
    fn format(&self, results: &AnalysisResults) -> Result<String>;
    fn file_extension(&self) -> &str;
}
```

### Example Formatter

```rust
pub struct MyFormatter;

impl OutputFormatter for MyFormatter {
    fn name(&self) -> &str {
        "my-format"
    }
    
    fn format(&self, results: &AnalysisResults) -> Result<String> {
        // Convert results to your format
        let output = serde_json::to_string_pretty(results)?;
        Ok(output)
    }
    
    fn file_extension(&self) -> &str {
        "myformat"
    }
}
```

## Testing

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests for specific module
cargo test analyzers::code

# Run tests with output
cargo test -- --nocapture

# Run tests in parallel
cargo test -- --test-threads=4
```

### Integration Tests

```bash
# Run integration test suite
python test/run_integration_tests.py

# Run specific test category
python test/run_integration_tests.py --category analyzers

# Run with specific test files
python test/run_integration_tests.py test/fixtures/python/
```

### Adding Test Cases

Create test files in `test/fixtures/`:

```
test/fixtures/
├── python/
│   ├── good/              # Code that should pass
│   │   ├── clean_code.py
│   │   └── good_imports.py
│   └── bad/              # Code that should fail  
│       ├── hallucinated.py
│       └── security_issues.py
├── javascript/
│   ├── good/
│   └── bad/
└── expected_results/     # Expected analysis results
    ├── python_good_results.json
    └── python_bad_results.json
```

## Documentation

### Building Documentation

```bash
# Install mdBook
cargo install mdbook

# Build docs
cd docs/
mdbook build

# Serve locally with live reload
mdbook serve --open
```

### Writing Documentation

- Use clear, concise language
- Include practical examples
- Add code snippets with expected output
- Test all commands and examples
- Use proper markdown formatting

### Documentation Standards

- **Headings**: Use sentence case ("Getting started", not "Getting Started")
- **Code blocks**: Always specify language for syntax highlighting
- **Commands**: Show full commands with expected output
- **Links**: Use relative links within the documentation
- **Images**: Include alt text and keep images under 1MB

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes

### Release Checklist

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md** with new features/fixes
3. **Run full test suite**: `cargo test && python test/run_integration_tests.py`
4. **Build documentation**: `mdbook build docs/`
5. **Create release PR** and get approval
6. **Tag release**: `git tag v1.2.3`
7. **Push tag**: `git push origin v1.2.3`
8. **GitHub Actions** will build and publish releases

## Community Guidelines

### Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/). Please:
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Report unacceptable behavior to the maintainers

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Requests**: Code review and collaboration

## Getting Help

### For Contributors

- Check existing issues and PRs first
- Read this contributing guide thoroughly
- Look at recent PRs for examples
- Ask questions in GitHub Discussions

### For Maintainers

- Review PRs promptly and constructively
- Help new contributors get started
- Maintain coding standards
- Keep documentation up to date

## Recognition

Contributors are recognized in:
- `CONTRIBUTORS.md` file
- Release notes
- Annual contributor spotlight

Thank you for helping make Vow better! 🙏

---

## Quick Reference

### Common Commands
```bash
# Development build
cargo build

# Run tests  
cargo test

# Format code
cargo fmt

# Check code quality
cargo clippy

# Build docs
mdbook build docs/

# Test rules
vow rules test rules/my-rules.yaml test.py
```

### Useful Resources
- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Guide](https://doc.rust-lang.org/cargo/)
- [mdBook Guide](https://rust-lang.github.io/mdBook/)
- [Conventional Commits](https://www.conventionalcommits.org/)