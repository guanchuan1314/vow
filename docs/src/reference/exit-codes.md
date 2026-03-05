# Exit Codes

Reference for all exit codes returned by Vow commands.

## Standard Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | No issues found, operation completed successfully |
| 1 | Issues Found | Analysis found issues (severity depends on --min-severity) |
| 2 | Configuration Error | Invalid configuration file or options |
| 3 | Model/Analyzer Error | ML model loading or analyzer execution failed |
| 4 | File I/O Error | Cannot read input files or write output |
| 5 | Network Error | Failed to download models or updates |
| 10 | Internal Error | Unexpected internal error |

## Usage in Scripts

```bash
#!/bin/bash

vow check script.py
exit_code=$?

case $exit_code in
  0)
    echo "✅ No issues found"
    ;;
  1)
    echo "⚠️  Issues found, review needed"
    ;;
  2)
    echo "❌ Configuration error"
    exit 1
    ;;
  *)
    echo "❌ Unexpected error (code: $exit_code)"
    exit 1
    ;;
esac
```

## CI/CD Integration

Use exit codes to control build behavior:
- **Exit 0**: Continue build
- **Exit 1**: Continue with warnings or fail based on policy
- **Exit 2+**: Fail build immediately

*This page is under development. See [CI/CD Integration](../guide/ci-cd-integration.md) for practical examples.*