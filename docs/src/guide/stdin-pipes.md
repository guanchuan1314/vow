# Stdin and Pipes

Use Vow with pipes and stdin for flexible integration with other tools.

## Basic Stdin Usage

```bash
# Check code from clipboard
pbpaste | vow check --stdin

# Check git diff before committing
git diff --cached | vow check --stdin --format table

# Pipe from other commands
cat script.py | vow check --stdin --analyzers code
```

## Integration Examples

```bash
# Check only changed files in git
git diff --name-only --cached | xargs vow check

# Process multiple files
find . -name "*.py" | xargs vow check --format json
```

*This page is under development. See [CLI Reference](../reference/cli-reference.md) for complete stdin options.*