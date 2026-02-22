# Known Packages

Manage the database of known packages for hallucination detection.

## Package Database

Vow maintains databases of known packages for each language:
- **Python**: PyPI packages + standard library
- **JavaScript**: NPM packages + Node.js built-ins
- **Go**: Go modules + standard library
- **Rust**: Crates.io + standard library

## Managing Packages

```bash
# List known packages
vow packages list --language python

# Update package database
vow packages update

# Add custom package
vow packages add my-internal-lib --language python
```

## Custom Package Lists

```yaml
# .vow/known-packages.yaml
custom_packages:
  python:
    - name: "internal_utils"
      versions: ["1.0.0", "1.1.0"]
  javascript:
    - name: "@company/shared"
      versions: [">=2.0.0"]
```

*This page is under development. See [Hallucination Detection](../analyzers/hallucination-detection.md) for detailed examples.*