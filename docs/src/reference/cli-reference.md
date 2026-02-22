# CLI Reference

This page provides a comprehensive reference for all Vow command-line options and subcommands.

## Global Options

These options are available for all commands:

```
--version              Show version information
--help                 Show help message
--config <FILE>        Use custom configuration file
--verbose, -v          Enable verbose output
--quiet, -q            Suppress non-error output
--color <WHEN>         When to use color (auto, always, never)
```

## Main Commands

### `vow check` - Analyze Files

Analyze files, directories, or stdin for AI output issues.

#### Syntax
```bash
vow check [OPTIONS] [PATH...]
vow check --stdin [OPTIONS]
```

#### Options

**Input Options:**
```
--stdin                    Read from stdin instead of files
--include <PATTERN>        Include files matching pattern (can be used multiple times)
--exclude <PATTERN>        Exclude files matching pattern (can be used multiple times)
--max-file-size <SIZE>     Skip files larger than SIZE (e.g., 10MB)
--follow-symlinks          Follow symbolic links
```

**Analyzer Options:**
```
--analyzers <LIST>         Comma-separated list of analyzers to use
                          (code, text, security, all)
--exclude-analyzers <LIST> Analyzers to exclude
--strictness <LEVEL>       Detection strictness (low, medium, high, paranoid)
--no-ml-models            Skip machine learning models (faster, less accurate)
--model-size <SIZE>        Model size to use (small, medium, large)
```

**Output Options:**
```
--format <FORMAT>          Output format (json, sarif, table, html)
--output <FILE>            Write output to file instead of stdout
--min-severity <LEVEL>     Minimum severity to report (info, low, medium, high)
--trust-score-only         Only show trust score, no detailed issues
--show-context             Include code context around issues
--no-color                 Disable colored output
```

**Performance Options:**
```
--jobs <N>                 Number of parallel jobs (default: CPU count)
--cache                    Use cache for unchanged files
--no-cache                 Disable caching
--timeout <SECONDS>        Maximum time per file (default: 30)
```

#### Examples

```bash
# Basic file check
vow check script.py

# Check directory with specific analyzers
vow check ./src --analyzers code,security

# Check with custom output format
vow check . --format sarif --output results.sarif

# Check from stdin
cat file.py | vow check --stdin --format table

# Check with specific file patterns
vow check . --include "*.py" --include "*.js" --exclude "test_*"

# High-strictness check for critical code
vow check production/ --strictness high --min-severity medium
```

### `vow setup` - Initialize and Configure

Download models and set up Vow for first use.

#### Syntax
```bash
vow setup [OPTIONS]
```

#### Options
```
--models <LIST>           Models to download (code,text,security,all)
--model-size <SIZE>       Model size to download (small,medium,large)
--mirror <REGION>         Download mirror (us,eu,cn)
--no-verify              Skip model integrity verification
--offline                Install using cached/bundled models only
--force                  Reinstall even if models exist
```

#### Examples
```bash
# Download all default models
vow setup

# Download specific models only
vow setup --models code,security

# Use European mirror
vow setup --mirror eu

# Reinstall models
vow setup --force
```

### `vow config` - Configuration Management

Manage Vow configuration files and settings.

#### Syntax
```bash
vow config <SUBCOMMAND> [OPTIONS]
```

#### Subcommands

**`vow config show`** - Display current configuration
```bash
vow config show [--format json|yaml|table]
```

**`vow config init`** - Create configuration file
```bash
vow config init [--global] [--template <TEMPLATE>]
```

**`vow config validate`** - Validate configuration
```bash
vow config validate [<CONFIG_FILE>]
```

**`vow config edit`** - Open configuration in editor
```bash
vow config edit [--global]
```

#### Examples
```bash
# Show current configuration
vow config show

# Create project configuration file
vow config init

# Create global configuration
vow config init --global

# Validate custom config file
vow config validate my-config.yaml
```

### `vow analyzers` - Analyzer Management

List, install, and manage analyzers.

#### Syntax
```bash
vow analyzers <SUBCOMMAND> [OPTIONS]
```

#### Subcommands

**`vow analyzers list`** - List available analyzers
```bash
vow analyzers list [--installed-only]
```

**`vow analyzers install`** - Install custom analyzer
```bash
vow analyzers install <WASM_FILE> [--name <NAME>]
```

**`vow analyzers remove`** - Remove analyzer
```bash
vow analyzers remove <NAME>
```

**`vow analyzers validate`** - Validate analyzers
```bash
vow analyzers validate [<ANALYZER>]
```

#### Examples
```bash
# List all analyzers
vow analyzers list

# Install custom analyzer
vow analyzers install my-analyzer.wasm --name custom

# Remove analyzer
vow analyzers remove custom
```

### `vow packages` - Package Database Management

Manage known package databases for hallucination detection.

#### Syntax
```bash
vow packages <SUBCOMMAND> [OPTIONS]
```

#### Subcommands

**`vow packages list`** - List known packages
```bash
vow packages list [--language <LANG>] [--search <PATTERN>]
```

**`vow packages update`** - Update package database
```bash
vow packages update [--language <LANG>] [--source <SOURCE>]
```

**`vow packages add`** - Add custom package
```bash
vow packages add <PACKAGE> --language <LANG> [--version <VER>]
```

**`vow packages export`** - Export package list
```bash
vow packages export <FILE> [--language <LANG>]
```

**`vow packages import`** - Import package list
```bash
vow packages import <FILE> [--merge]
```

#### Examples
```bash
# List Python packages
vow packages list --language python

# Search for specific packages
vow packages list --search "requests"

# Update all package databases
vow packages update

# Add internal package
vow packages add company-utils --language python --version "1.0.0"

# Export team package list
vow packages export team-packages.yaml
```

### `vow rules` - Rule Management

Manage custom detection rules.

#### Syntax
```bash
vow rules <SUBCOMMAND> [OPTIONS]
```

#### Subcommands

**`vow rules list`** - List available rules
```bash
vow rules list [--builtin] [--custom]
```

**`vow rules validate`** - Validate rule file
```bash
vow rules validate <RULE_FILE>
```

**`vow rules test`** - Test rules against sample code
```bash
vow rules test <RULE_FILE> <CODE_FILE>
```

**`vow rules create`** - Create rule template
```bash
vow rules create <NAME> [--template <TYPE>]
```

#### Examples
```bash
# List all rules
vow rules list

# Validate custom rules
vow rules validate my-rules.yaml

# Test rules against sample
vow rules test my-rules.yaml sample.py

# Create new rule template
vow rules create detect-deprecated --template python
```

## Exit Codes

Vow uses these exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success, no issues found |
| 1 | Issues found (severity depends on --min-severity) |
| 2 | Configuration error |
| 3 | Model/analyzer error |
| 4 | File I/O error |
| 5 | Network error (during setup/updates) |
| 10 | Internal error |

## Environment Variables

Configure Vow behavior with environment variables:

```bash
# Configuration
VOW_CONFIG_FILE=/path/to/config.yaml    # Default config file
VOW_DATA_DIR=/path/to/data               # Data directory
VOW_CACHE_DIR=/path/to/cache             # Cache directory

# Output
VOW_NO_COLOR=1                           # Disable colored output
VOW_QUIET=1                              # Suppress output
VOW_VERBOSE=1                            # Enable verbose output

# Performance
VOW_JOBS=4                               # Parallel jobs
VOW_TIMEOUT=60                           # Timeout per file (seconds)
VOW_MAX_FILE_SIZE=10MB                   # Maximum file size

# Network
VOW_OFFLINE=1                            # Disable network requests
VOW_PROXY=http://proxy.example.com:8080  # HTTP proxy
VOW_MIRROR=eu                            # Download mirror

# Models
VOW_MODEL_SIZE=small                     # Default model size
VOW_NO_ML=1                             # Disable ML models
```

## Configuration Files

Vow looks for configuration files in this order:

1. File specified by `--config` or `VOW_CONFIG_FILE`
2. `.vow.yaml` in current directory
3. `.vow.yaml` in parent directories (walking up)
4. `~/.config/vow/config.yaml` (user config)
5. `/etc/vow/config.yaml` (system config)

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
vow completion bash > /etc/bash_completion.d/vow

# Zsh
vow completion zsh > ~/.zfunc/_vow

# Fish
vow completion fish > ~/.config/fish/completions/vow.fish

# PowerShell
vow completion powershell > vow.ps1
```

## API Mode

Run Vow as a daemon for IDE integration:

```bash
# Start API server
vow daemon --port 8080 --bind 127.0.0.1

# Check API status
curl http://localhost:8080/status

# Analyze via API
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{"code": "import fake_lib", "language": "python"}'
```

## Debug Mode

Enable debug mode for troubleshooting:

```bash
# Debug specific analyzer
vow check file.py --debug-analyzer code

# Full debug output
vow check file.py --debug

# Trace mode (very verbose)
VOW_LOG_LEVEL=trace vow check file.py
```

## Next Steps

- [Configuration File](../configuration/config-file.md) - Detailed configuration options
- [Output Formats](output-formats.md) - Understanding output formats
- [Exit Codes](exit-codes.md) - Detailed exit code reference