# Text Analyzer

The text analyzer identifies issues in natural language content, including fabricated facts, broken references, and inconsistent information.

## Analysis Features

### Factual Consistency
Checks statements against known factual databases and identifies potential fabrications.

### Reference Validation
Validates URLs, citations, and external references for accessibility and accuracy.

### Writing Pattern Analysis
Detects unnatural writing patterns that may indicate AI generation.

### Internal Consistency
Finds contradictions and inconsistencies within the same document.

## Configuration

```yaml
# .vow.yaml
analyzers:
  text:
    enabled: true
    check_urls: true
    fact_checking: true
```

*This page is under development. See [Analyzers Overview](overview.md) for current capabilities.*