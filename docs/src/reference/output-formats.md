# Output Formats

Vow supports multiple output formats for different use cases.

## Available Formats

### JSON Format
```bash
vow check . --format json
```
Machine-readable format for programmatic processing.

### SARIF Format  
```bash
vow check . --format sarif
```
Static Analysis Results Interchange Format - ideal for CI/CD and security tools.

### Table Format
```bash  
vow check . --format table
```
Human-readable tabular output for terminal usage.

### HTML Format
```bash
vow check . --format html --output report.html
```
Rich HTML report with interactive features.

## Format Examples

### JSON Output
```json
{
  "files": [
    {
      "path": "script.py",
      "trust_score": 0.7,
      "issues": [
        {
          "rule": "hallucinated-import",
          "severity": "high",
          "message": "Import not found",
          "line": 1,
          "column": 0
        }
      ]
    }
  ],
  "summary": {
    "total_files": 1,
    "trust_score_avg": 0.7
  }
}
```

*This page is under development. See [CLI Reference](cli-reference.md) for all format options.*