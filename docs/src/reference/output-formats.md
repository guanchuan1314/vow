# Output Formats

Vow supports multiple output formats optimized for different use cases, from human consumption to CI/CD automation.

## Available Formats

### JSON Format (`--format json`)
```bash
vow check . --format json
```
Machine-readable format ideal for CI/CD pipelines, automation scripts, and programmatic processing. Includes performance summaries and detailed issue information.

### Table Format (`--format table`) 
```bash  
vow check . --format table
```
Human-readable tabular output for terminal usage with color-coded severity levels and trust scores.

### SARIF Format (`--format sarif`)
```bash
vow check . --format sarif
```
Static Analysis Results Interchange Format - standardized format for security tools and IDE integration.

### HTML Format (`--format html`)
```bash
vow check . --format html --output report.html
```
Rich HTML report with interactive features, filtering, and embedded CSS for standalone viewing.

## Format Examples

### JSON Output (Recommended for CI/CD)
```json
{
  "files": [
    {
      "path": "script.py",
      "trust_score": 0.7,
      "language": "python",
      "size_bytes": 1247,
      "issues": [
        {
          "rule": "hallucinated-import",
          "severity": "high",
          "message": "Import 'nonexistent_lib' not found in known packages",
          "line": 2,
          "column": 1,
          "context": "from nonexistent_lib import magic_function",
          "suggestion": "Verify this import exists or add to known packages"
        },
        {
          "rule": "suspicious-api",
          "severity": "medium",
          "message": "API endpoint may be fabricated",
          "line": 6,
          "column": 25,
          "context": "requests.get('https://api.fake.com/users')"
        }
      ]
    }
  ],
  "summary": {
    "total_files": 1,
    "files_analyzed": 1,
    "files_with_issues": 1,
    "total_issues": 2,
    "trust_score_avg": 0.7,
    "issues_by_severity": {
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    }
  },
  "performance": {
    "duration_ms": 152,
    "files_per_second": 35.2,
    "bytes_processed": 1247,
    "skipped_files": 0,
    "memory_usage_mb": 12.4
  },
  "metadata": {
    "vow_version": "1.2.0",
    "scan_time": "2024-01-15T10:30:45Z",
    "analyzers_used": ["code", "text", "security"],
    "languages_detected": ["python"]
  }
}
```

### Table Output
```
┌─────────────────┬──────────────┬──────────┬─────────────────────────────────────────────┐
│ File            │ Line:Col     │ Severity │ Issue                                       │
├─────────────────┼──────────────┼──────────┼─────────────────────────────────────────────┤
│ script.py       │ 2:1          │ HIGH     │ Import 'nonexistent_lib' not found         │
│ script.py       │ 6:25         │ MEDIUM   │ API endpoint may be fabricated              │
└─────────────────┴──────────────┴──────────┴─────────────────────────────────────────────┘

Summary:
  Files analyzed: 1 (35.2 files/sec)
  Issues found: 2
  Trust Score: 0.7/1.0 (Medium confidence)
  Duration: 152ms
```

### SARIF Output
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Vow",
          "version": "1.2.0",
          "informationUri": "https://getvow.dev"
        }
      },
      "results": [
        {
          "ruleId": "hallucinated-import",
          "level": "error",
          "message": {
            "text": "Import 'nonexistent_lib' not found in known packages"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "script.py"
                },
                "region": {
                  "startLine": 2,
                  "startColumn": 1
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Performance Summaries

All output formats include performance summaries when using `--verbose`:

### Key Metrics
- **Files per second**: Processing throughput
- **Duration**: Total analysis time
- **Memory usage**: Peak memory consumption
- **Files skipped**: Files excluded by .vowignore or filters
- **Bytes processed**: Total content analyzed

### CI/CD Integration

The JSON format is optimized for CI/CD workflows:

```yaml
# GitHub Actions example
- name: Run Vow Analysis
  run: vow check . --format json --output results.json
  
- name: Process Results
  run: |
    ISSUES=$(jq '.summary.total_issues' results.json)
    if [ "$ISSUES" -gt 0 ]; then
      echo "Found $ISSUES issues in AI-generated content"
      exit 1
    fi
```

## Format Selection Guide

| Use Case | Recommended Format | Rationale |
|----------|-------------------|-----------|
| Terminal usage | `table` | Human-readable, color-coded |
| CI/CD pipelines | `json` | Machine-readable, complete data |
| Security tools | `sarif` | Industry standard format |
| Reports & sharing | `html` | Rich presentation, self-contained |
| IDE integration | `sarif` | Native support in most IDEs |
| Scripting | `json` | Easy to parse with standard tools |

## Output Options

Control output verbosity and content:

```bash
# Minimal output - just issues
vow check . --quiet --format json

# Verbose output - includes performance data  
vow check . --verbose --format table

# Only trust scores
vow check . --trust-score-only

# Include code context
vow check . --show-context --format json

# Filter by severity
vow check . --min-severity medium --format table
```

## File Output

Save results to files for later analysis:

```bash
# Save JSON results
vow check . --format json --output analysis.json

# Save HTML report
vow check . --format html --output report.html

# Save SARIF for security tools
vow check . --format sarif --output vow-results.sarif
```

---

For more output customization options, see the [CLI Reference](cli-reference.md).