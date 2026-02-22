# Configuration File

Customize Vow's behavior with configuration files in YAML format.

## Configuration File Locations

Vow looks for configuration files in this order:
1. `--config` command line option
2. `.vow.yaml` in current directory  
3. `.vow.yaml` in parent directories
4. `~/.config/vow/config.yaml` (user config)
5. `/etc/vow/config.yaml` (system config)

## Basic Configuration

```yaml
# .vow.yaml
analyzers:
  enabled:
    - code
    - text
    - security
  
  strictness: medium

output:
  format: table
  min_severity: medium
  show_trust_score: true

trust_score:
  weights:
    code: 0.4
    text: 0.35
    security: 0.25
```

## Creating Configuration

```bash
# Create project configuration template
vow config init

# Create global configuration
vow config init --global

# Validate configuration
vow config validate
```

*This page is under development. See [CLI Reference](../reference/cli-reference.md) for all configuration options.*