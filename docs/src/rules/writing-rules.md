# Writing Rules

Learn how to write custom detection rules for your specific use cases.

## Rule Structure

```yaml
name: "My Rule Set"
version: "1.0.0"
description: "Custom rules for my project"

rules:
  - id: "rule-id"
    name: "Human-readable name"
    description: "Detailed description"
    severity: "medium"  # info, low, medium, high
    
    # Pattern matching
    patterns:
      - regex: "pattern"
        message: "Issue description"
    
    # Language-specific patterns
    languages:
      python:
        - regex: "python-specific-pattern"
      javascript:
        - regex: "js-specific-pattern"
```

## Pattern Types

### Regular Expressions
```yaml
patterns:
  - regex: "\\bforbidden_function\\("
    message: "This function is not allowed"
```

### Context-aware Rules
```yaml
contexts:
  - type: "function"
    patterns:
      - regex: "eval\\("
        message: "eval() in functions is dangerous"
```

*This page is under development. See [Rules Overview](overview.md) for examples.*