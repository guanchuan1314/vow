# Checking Files

Learn advanced techniques for analyzing individual files with Vow.

## Single File Analysis

```bash
# Basic file check
vow check script.py

# With specific analyzers
vow check script.py --analyzers code,security

# Verbose output with explanations
vow check script.py --verbose
```

## File Type Detection

Vow automatically detects file types and applies appropriate analyzers:

- **Python files** (`.py`) → Code + Security analyzers
- **JavaScript files** (`.js`, `.ts`) → Code + Security analyzers  
- **Markdown files** (`.md`) → Text analyzer
- **Configuration files** (`.yaml`, `.json`) → Security analyzer

## Advanced Options

See [CLI Reference](../reference/cli-reference.md) for complete options.

*This page is under development. See [Quick Start](../getting-started/quick-start.md) for current examples.*