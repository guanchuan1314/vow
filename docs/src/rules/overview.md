# Rules Overview

Vow uses a flexible rule engine to detect patterns and issues in AI-generated content.

## Built-in Rules

Vow comes with built-in rules for common issues:
- **hallucinated-import**: Non-existent package imports
- **hallucinated-api**: Fabricated API endpoints
- **security-hardcoded-secret**: Hardcoded credentials
- **text-broken-reference**: Invalid URLs or citations

## Custom Rules

Write custom rules in YAML format:

```yaml
# custom-rules.yaml
name: "My Custom Rules"
version: "1.0.0"

rules:
  - id: "no-eval"
    name: "Prohibit eval() usage"
    severity: "high"
    patterns:
      - regex: "\\beval\\("
        message: "eval() is dangerous and should not be used"
```

## Using Rules

```bash
# List available rules
vow rules list

# Validate rule file
vow rules validate custom-rules.yaml

# Test rules
vow rules test custom-rules.yaml sample.py
```

*This page is under development. See [Writing Rules](writing-rules.md) for detailed syntax.*