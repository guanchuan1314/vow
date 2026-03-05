# Checking Directories

Learn how to analyze entire directories and projects with Vow.

## Directory Analysis

```bash
# Check all files in current directory
vow check .

# Check specific directory
vow check src/

# Include/exclude patterns
vow check . --include "*.py" --exclude "test_*"
```

## Performance Tips

- Use `--jobs N` for parallel processing
- Cache results with `--cache`
- Set file size limits with `--max-file-size`

*This page is under development. See [CI/CD Integration](ci-cd-integration.md) for advanced examples.*