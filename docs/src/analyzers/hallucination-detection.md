# Hallucination Detection

The hallucination detection analyzer is Vow's core feature, designed to identify when AI models generate fabricated APIs, imports, functions, or other non-existent code elements.

## How It Works

### The Allowlist Approach

Vow uses an **allowlist-based approach** to detect hallucinations:

1. **Known Package Database**: Maintains a curated list of real packages, APIs, and functions
2. **Import Verification**: Checks if imported packages actually exist
3. **API Validation**: Verifies that called functions/methods are real
4. **Cross-reference**: Compares generated code against known good patterns

```python
# ✅ Real import - will pass
import requests
response = requests.get("https://api.github.com/users/octocat")

# ❌ Hallucinated import - will be flagged
import nonexistent_magic_lib
data = nonexistent_magic_lib.do_impossible_thing()
```

### Detection Mechanisms

#### 1. Import Analysis
```python
# Real imports (in allowlist)
import os                    # ✅ Standard library
import requests              # ✅ Popular package
from flask import Flask      # ✅ Known framework

# Hallucinated imports (not in allowlist)
import magic_ai_lib          # ❌ Doesn't exist
from super_utils import *    # ❌ Vague/fabricated
import openai_v4             # ❌ Version doesn't exist
```

#### 2. API Endpoint Validation
```python
# Suspicious API patterns
requests.get("https://api.nonexistent.com/v1/data")    # ❌ Fake domain
requests.post("https://api.example.com/secret")        # ❌ Too generic
fetch("https://internal-api.company.com/admin")        # ❌ Assumed internal API
```

#### 3. Function Call Verification
```python
# Real function calls
os.path.exists("/tmp")           # ✅ Standard library
requests.get().json()            # ✅ Known method chain

# Hallucinated function calls  
requests.get().auto_parse()      # ❌ Method doesn't exist
os.smart_cleanup()               # ❌ Function doesn't exist
```

## Supported Languages

| Language | Import Detection | API Validation | Function Verification | Coverage |
|----------|------------------|----------------|----------------------|----------|
| **Python** | ✅ Full | ✅ Full | ✅ Full | 95%+ |
| **JavaScript** | ✅ Full | ✅ Partial | ✅ Full | 85%+ |
| **TypeScript** | ✅ Full | ✅ Partial | ✅ Full | 85%+ |
| **Go** | ✅ Full | ❌ Limited | ✅ Partial | 70%+ |
| **Rust** | ✅ Full | ❌ Limited | ✅ Partial | 65%+ |
| **Java** | 🔄 Coming Soon | 🔄 Coming Soon | 🔄 Coming Soon | - |

## Known Package Database

### Python Packages
Vow includes knowledge of:
- **Standard Library**: All built-in modules (os, sys, json, etc.)
- **Popular Packages**: Top 1000 PyPI packages by download count
- **Common Patterns**: Typical import styles and usage patterns

```yaml
# Example Python package definitions
python_packages:
  requests:
    version_range: ">=2.0.0"
    common_imports:
      - "import requests"
      - "from requests import get, post"
    known_methods:
      - "get"
      - "post" 
      - "put"
      - "delete"
    common_patterns:
      - "requests.get().json()"
      - "requests.post(url, json=data)"
```

### JavaScript/Node.js Packages
- **Built-ins**: All Node.js core modules
- **NPM Popular**: Top 500 most downloaded packages
- **Browser APIs**: DOM, Fetch, etc.

### Custom Package Lists
Add your organization's internal packages:

```yaml
# .vow/known-packages.yaml
custom_packages:
  python:
    - name: "internal_utils"
      versions: ["1.0.0", "1.1.0"]
      imports:
        - "from internal_utils import helper"
    - name: "company_api_client"
      versions: [">=2.0.0"]
```

## Configuration

### Basic Configuration
```yaml
# .vow.yaml
analyzers:
  hallucination_detection:
    enabled: true
    
    # Strictness level
    strictness: medium  # low, medium, high, paranoid
    
    # Package sources to check
    check_sources:
      - pypi          # Python Package Index
      - npm           # NPM Registry
      - crates_io     # Rust Crates
      - custom        # Your custom packages
    
    # What to check
    check_types:
      - imports       # import statements
      - api_calls     # HTTP API endpoints
      - functions     # Function/method calls
```

### Strictness Levels

#### Low Strictness
- Only flags obviously fake packages
- Allows common placeholder names
- Minimal false positives

```python
# Would NOT be flagged in low strictness
import utils              # Generic but common
from helpers import *     # Vague but acceptable
```

#### Medium Strictness (Default)
- Balanced approach
- Flags suspicious patterns
- Some false positives acceptable

```python
# Would be flagged in medium strictness
import magic_helper       # "magic" is suspicious
from ai_utils import *    # AI-related names are suspicious
```

#### High Strictness  
- Very conservative
- Flags anything not explicitly known
- Higher false positive rate

```python
# Would be flagged in high strictness
import custom_lib         # Not in allowlist
import internal_tool      # Unknown package
```

#### Paranoid Mode
- Maximum detection
- Flags even borderline cases
- High false positive rate but catches everything

## Limitations

### 1. Custom/Internal Packages
Vow doesn't know about your internal packages by default:

```python
# Will be flagged even if these are real internal packages
import company_internal_lib
from team_utils import helper
```

**Solution**: Add them to your custom package list.

### 2. Version-Specific APIs
Vow may not track every version of every package:

```python
# Might be flagged if using very new features
import requests
response = requests.get(url, timeout=30.5)  # New timeout format
```

### 3. Dynamic Imports
Runtime imports are harder to verify:

```python
# Harder to verify statically
module_name = "requests" 
imported_module = __import__(module_name)
```

### 4. Language Coverage
Some languages have limited coverage - see the table above.

## Fine-tuning

### Reducing False Positives

#### 1. Custom Allowlist
```yaml
# .vow/known-packages.yaml
allowlist:
  python:
    - "internal_package"
    - "legacy_tool"
  javascript:
    - "@company/utils"
```

#### 2. Ignore Patterns
```yaml
# .vow.yaml
hallucination_detection:
  ignore_patterns:
    - "test_*"           # Test files often have mock imports
    - "*_mock"           # Mock modules
    - "example_*"        # Example code
```

#### 3. Confidence Thresholds
```yaml
hallucination_detection:
  confidence_threshold: 0.7  # Only flag high-confidence issues
  min_severity: medium       # Skip low-severity issues
```

### Handling Special Cases

#### Commented Code
```python
# This won't be flagged (commented)
# import fake_library

# This WILL be flagged (active code)
import fake_library
```

#### Documentation Examples
```yaml
# Mark documentation files as examples
file_types:
  documentation:
    patterns: ["*.md", "*.rst", "docs/**"]
    relaxed_checking: true
```

## Common Issues and Solutions

### Issue: Internal Package Flagged
```
❌ Import 'company_utils' not found in known packages
```

**Solution**: Add to custom allowlist
```yaml
custom_packages:
  python:
    - name: "company_utils"
```

### Issue: New Package Version
```
❌ Method 'requests.Session().mount()' may be hallucinated
```

**Solution**: Update package database or reduce strictness
```bash
# Update package database
vow update-packages

# Or reduce strictness for this project
vow check . --strictness low
```

### Issue: Dynamic Code
```python
# This pattern is hard to verify
getattr(requests, 'get')('https://api.example.com')
```

**Solution**: Use static imports when possible, or add ignore patterns.

## Best Practices

### 1. Regular Updates
Keep the package database updated:
```bash
# Update monthly
vow update-packages --auto-schedule monthly
```

### 2. Project-Specific Configuration
Create `.vow.yaml` files for each project:
```yaml
# For a data science project
analyzers:
  hallucination_detection:
    strictness: low  # Many ML packages
    custom_packages:
      - "internal_ml_utils"
```

### 3. CI Integration
Use in CI but handle false positives:
```yaml
# .github/workflows/vow.yml
- name: Check for hallucinations
  run: |
    vow check . --format sarif --output results.sarif
    # Continue on failure but upload results
  continue-on-error: true
```

### 4. Team Coordination
Share package lists across team:
```bash
# Export your package list
vow packages export team-packages.yaml

# Import on other machines
vow packages import team-packages.yaml
```

## Next Steps

- [Code Analyzer](code-analyzer.md) - Related code analysis features
- [Known Packages](../configuration/known-packages.md) - Managing package lists
- [Writing Rules](../rules/writing-rules.md) - Custom detection rules