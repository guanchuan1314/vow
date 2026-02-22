# Quick Start

This guide will get you up and running with Vow in just a few minutes. We'll check some AI-generated code and explore the basic features.

## Prerequisites

Make sure you have Vow installed. If not, see the [Installation](installation.md) guide.

## Your First Check

Let's start with a simple example. Create a test file with some AI-generated Python code:

```bash
# Create a test file
cat << 'EOF' > test_ai_code.py
import requests
from nonexistent_lib import magic_function

def fetch_user_data(user_id):
    """Fetch user data from the API"""
    # This API endpoint doesn't exist
    response = requests.get(f"https://api.example.com/v2/users/{user_id}")
    
    # Using a function that doesn't exist
    processed_data = magic_function(response.json())
    
    return processed_data

if __name__ == "__main__":
    data = fetch_user_data(123)
    print(data)
EOF
```

Now let's check this file with Vow:

```bash
vow check test_ai_code.py
```

You should see output like this:

```json
{
  "files": [
    {
      "path": "test_ai_code.py",
      "trust_score": 0.3,
      "issues": [
        {
          "rule": "hallucinated-import",
          "severity": "high",
          "message": "Import 'nonexistent_lib' not found in known packages",
          "line": 2,
          "column": 1
        },
        {
          "rule": "hallucinated-api",
          "severity": "medium", 
          "message": "API endpoint 'api.example.com/v2/users' may be fabricated",
          "line": 6,
          "column": 25
        }
      ]
    }
  ],
  "summary": {
    "total_files": 1,
    "files_with_issues": 1,
    "trust_score_avg": 0.3
  }
}
```

## Understanding the Output

Let's break down what Vow found:

- **Trust Score**: 0.3 (out of 1.0) indicates low confidence in this code
- **Hallucinated Import**: `nonexistent_lib` isn't a real Python package
- **Hallucinated API**: The API endpoint looks fabricated
- **Severity Levels**: `high`, `medium`, `low`, and `info`

## Different Output Formats

Vow supports multiple output formats:

### Human-readable format
```bash
vow check test_ai_code.py --format table
```
```
┌─────────────────┬──────────────┬──────────┬─────────────────────────────────────┐
│ File            │ Line:Col     │ Severity │ Issue                               │
├─────────────────┼──────────────┼──────────┼─────────────────────────────────────┤
│ test_ai_code.py │ 2:1          │ HIGH     │ Import 'nonexistent_lib' not found │
│ test_ai_code.py │ 6:25         │ MEDIUM   │ API endpoint may be fabricated      │
└─────────────────┴──────────────┴──────────┴─────────────────────────────────────┘

Trust Score: 0.3/1.0 (Low confidence)
```

### SARIF format (for CI/CD)
```bash
vow check test_ai_code.py --format sarif
```

### HTML report
```bash
vow check test_ai_code.py --format html --output report.html
```

## Checking Multiple Files

Vow can analyze entire directories:

```bash
# Check all files in current directory
vow check .

# Check specific file types
vow check . --include "*.py" --include "*.js"

# Exclude certain files
vow check . --exclude "test_*" --exclude "*.md"
```

## Using Stdin

You can also pipe content directly to Vow:

```bash
# Check code from clipboard
pbpaste | vow check --stdin

# Check git diff before committing
git diff --cached | vow check --stdin --format table
```

## Common Options

Here are some useful command-line options:

```bash
# Set minimum severity level
vow check file.py --min-severity medium

# Show only trust score
vow check file.py --trust-score-only

# Verbose output with explanations
vow check file.py --verbose

# Use specific analyzers only
vow check file.py --analyzers code,security

# Custom configuration file
vow check file.py --config custom.yaml
```

## Configuration File

Create a `.vow.yaml` file in your project root for persistent configuration:

```yaml
# .vow.yaml
analyzers:
  - code
  - text
  - security

severity:
  min_level: medium

output:
  format: table
  show_trust_score: true

rules:
  include:
    - hallucinated-import
    - security-pattern
  exclude:
    - minor-style-issue

known_packages:
  python:
    - requests
    - flask
    - django
  javascript:
    - react
    - express
    - lodash
```

## CI/CD Integration

Add Vow to your GitHub Actions workflow:

```yaml
# .github/workflows/vow-check.yml
name: AI Output Verification
on: [push, pull_request]

jobs:
  vow-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Vow
        run: |
          curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
          chmod +x vow
          sudo mv vow /usr/local/bin/
      - name: Check AI-generated content
        run: vow check . --format sarif --output vow-results.sarif
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vow-results.sarif
```

## What's Next?

Now that you have Vow up and running, explore these areas:

- **[Checking Files](../guide/checking-files.md)**: Learn advanced file checking techniques
- **[Configuration](../configuration/config-file.md)**: Customize Vow for your projects  
- **[Analyzers](../analyzers/overview.md)**: Deep dive into how each analyzer works
- **[Rules](../rules/writing-rules.md)**: Write custom rules for your domain
- **[CI/CD Integration](../guide/ci-cd-integration.md)**: Set up automated checks

## Getting Help

- View built-in help: `vow --help` or `vow check --help`
- Check configuration: `vow config show`
- List available analyzers: `vow analyzers list`
- Test rule syntax: `vow rules validate my_rules.yaml`