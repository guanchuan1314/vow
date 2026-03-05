# Trust Score Algorithm

The trust score is Vow's quantitative measure of confidence in AI-generated content. It ranges from 0.0 (very low confidence) to 1.0 (high confidence) and helps you prioritize which outputs need human review.

## How Trust Scores Work

### Basic Formula

```
Trust Score = weighted_average(analyzer_scores) × confidence_multiplier
```

Where:
- **Analyzer Scores**: Individual confidence ratings from each analyzer
- **Weights**: Importance weighting for each analyzer
- **Confidence Multiplier**: Adjustment based on detection certainty

### Default Weights

| Analyzer | Weight | Rationale |
|----------|--------|-----------|
| Code | 40% | Code issues are objective and verifiable |
| Text | 35% | Text analysis has good accuracy but some subjectivity |
| Security | 25% | Security issues are critical but less frequent |

## Analyzer-Specific Scoring

### Code Analyzer Scoring

The code analyzer evaluates several factors:

```yaml
code_factors:
  syntax_correctness: 25%     # Valid syntax and structure
  import_validity: 30%        # All imports are real packages
  api_authenticity: 25%       # Function/method calls exist
  pattern_consistency: 20%    # Follows common coding patterns
```

**Examples:**

```python
# High trust score (0.9+)
import requests
import json

def get_user(user_id):
    response = requests.get(f"https://api.github.com/users/{user_id}")
    return response.json()
```

```python
# Low trust score (0.3-)
import fake_requests_lib
import nonexistent_module

def magic_function():
    data = fake_requests_lib.auto_get_everything()
    return nonexistent_module.process_magically(data)
```

### Text Analyzer Scoring

Text analysis considers:

```yaml
text_factors:
  factual_consistency: 35%    # Statements align with known facts
  reference_validity: 25%     # URLs, citations are real
  writing_naturalness: 20%    # Human-like writing patterns
  internal_consistency: 20%   # No self-contradictions
```

**Examples:**

```markdown
<!-- High trust score -->
Python was created by Guido van Rossum and first released in 1991.
The latest stable version can be found at https://python.org.

<!-- Low trust score -->
Python was invented in 1995 by John Smith at Google Corporation.
Download it from https://python-official-new.com/downloads.
```

### Security Analyzer Scoring

Security scoring focuses on:

```yaml
security_factors:
  vulnerability_presence: 40%  # No dangerous patterns detected
  secret_exposure: 30%         # No hardcoded credentials
  permission_safety: 20%       # Safe privilege usage
  injection_resistance: 10%    # No injection vulnerabilities
```

## Score Interpretation

### Confidence Levels

| Score Range | Confidence | Color | Meaning | Action |
|------------|------------|--------|---------|---------|
| 0.8 - 1.0 | High | 🟢 Green | Likely reliable | Use with minimal review |
| 0.6 - 0.8 | Medium | 🟡 Yellow | Some concerns | Review before use |
| 0.3 - 0.6 | Low | 🟠 Orange | Multiple issues | Careful review required |
| 0.0 - 0.3 | Very Low | 🔴 Red | Likely problematic | Significant review needed |

### Score Modifiers

Trust scores can be adjusted by various factors:

#### Content Length Bonus
Longer, more detailed content gets slight bonuses:
```
length_bonus = min(0.1, log(content_length) / 100)
```

#### Consistency Bonus  
Content that passes multiple analyzers gets reinforcement:
```
if all_analyzers_agree:
    consistency_bonus = 0.05
```

#### Uncertainty Penalty
When analyzers disagree significantly:
```
if analyzer_disagreement > 0.3:
    uncertainty_penalty = 0.1
```

## Factors That Increase Trust Score

### ✅ Positive Indicators

**Code:**
- All imports are from well-known packages
- Function calls match documented APIs
- Follows established coding conventions
- Includes proper error handling
- Has realistic variable names

**Text:**
- Contains verifiable facts
- Uses real URLs and references
- Maintains consistent terminology
- Shows natural writing flow
- Includes appropriate caveats/disclaimers

**Security:**
- No hardcoded credentials
- Safe API usage patterns
- Proper input validation
- Appropriate error handling
- Following security best practices

### Examples of High-Trust Content

```python
# Score: 0.92 - Very trustworthy
import requests
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

def fetch_github_user(username: str) -> Optional[Dict]:
    """Fetch user data from GitHub API."""
    try:
        url = f"https://api.github.com/users/{username}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch user {username}: {e}")
        return None
```

## Factors That Decrease Trust Score

### ❌ Negative Indicators

**Code:**
- Imports from non-existent packages
- Calls to fabricated functions
- Unusual or "magical" variable names
- Missing error handling
- Unrealistic functionality claims

**Text:**
- Contradicts known facts
- Contains broken links/references
- Has unnatural writing patterns
- Makes unsupported claims
- Contains AI-typical phrases

**Security:**
- Hardcoded API keys or passwords
- Dangerous function usage (eval, exec)
- Missing input validation
- Overly permissive operations
- Injection vulnerability patterns

### Examples of Low-Trust Content

```python
# Score: 0.15 - Very suspicious
import magic_ai_utils
import super_advanced_ml

def solve_everything(problem):
    # This function can solve any problem automatically
    solution = magic_ai_utils.auto_solve(problem)
    enhanced_solution = super_advanced_ml.make_it_perfect(solution)
    return enhanced_solution.get_final_answer()
```

## Customizing Trust Score Calculation

### Adjust Analyzer Weights

```yaml
# .vow.yaml
trust_score:
  weights:
    code: 0.5      # Increase code analyzer importance
    text: 0.3      # Decrease text analyzer importance  
    security: 0.2  # Keep security weight the same
```

### Set Custom Thresholds

```yaml
trust_score:
  thresholds:
    high: 0.85     # Raise bar for "high confidence"
    medium: 0.65   # Custom medium threshold
    low: 0.35      # Custom low threshold
```

### Domain-Specific Scoring

```yaml
# For data science projects
trust_score:
  domain: data_science
  weights:
    code: 0.3      # Less emphasis on perfect imports
    text: 0.4      # More emphasis on documentation
    security: 0.3  # Higher security concern for data
```

## Understanding Score Components

### Detailed Breakdown

Get detailed scoring information:

```bash
# Show score breakdown
vow check file.py --show-score-breakdown

# Output includes:
# - Individual analyzer scores
# - Weight contributions  
# - Applied modifiers
# - Final calculation
```

Example output:
```json
{
  "trust_score": 0.73,
  "breakdown": {
    "code_analyzer": {
      "score": 0.8,
      "weight": 0.4,
      "contribution": 0.32,
      "factors": {
        "import_validity": 0.9,
        "api_authenticity": 0.7,
        "syntax_correctness": 1.0,
        "pattern_consistency": 0.6
      }
    },
    "text_analyzer": {
      "score": 0.65,
      "weight": 0.35,
      "contribution": 0.23
    },
    "security_analyzer": {
      "score": 0.9,
      "weight": 0.25,
      "contribution": 0.23
    },
    "modifiers": {
      "length_bonus": 0.02,
      "consistency_bonus": 0.0,
      "uncertainty_penalty": -0.05
    }
  }
}
```

## Trust Score in CI/CD

### Setting Thresholds

```yaml
# GitHub Actions example
- name: Check AI output quality
  run: |
    vow check . --min-trust-score 0.7 --format sarif
    
# Exit codes based on trust score:
# 0: All files meet threshold
# 1: Some files below threshold  
# 2: Critical issues found
```

### Gradual Rollout

```yaml
# Gradually increase standards
trust_score:
  thresholds:
    # Week 1: Get baseline
    required: 0.3
    
    # Week 2: Eliminate worst content  
    # required: 0.5
    
    # Week 3: Raise the bar
    # required: 0.7
```

## Best Practices

### 1. Use Trust Scores as Guidelines
- Don't rely solely on scores for critical decisions
- Combine with human review for important content
- Consider context and domain requirements

### 2. Establish Team Standards
```yaml
# team-standards.yaml
trust_score:
  production_code: 0.8    # High bar for production
  documentation: 0.6      # Medium bar for docs
  examples: 0.4           # Lower bar for examples
  tests: 0.5              # Medium bar for tests
```

### 3. Monitor Score Distribution
```bash
# Get score statistics for your codebase
vow check . --stats --format json | jq '.trust_score_distribution'
```

### 4. Track Improvements
```bash
# Compare scores over time
vow check . --output baseline.json
# ... make improvements ...
vow check . --output improved.json --compare baseline.json
```

## Limitations

### What Trust Scores Can't Tell You

- **Domain Expertise**: Scores can't evaluate domain-specific correctness
- **Business Logic**: Can't verify if code meets business requirements  
- **Performance**: Doesn't measure code efficiency or scalability
- **User Experience**: Can't assess UI/UX quality
- **Integration**: Doesn't verify how code works with other systems

### When to Ignore Trust Scores

- **Prototype/Experimental Code**: Lower scores expected
- **Legacy Code Integration**: May trigger false positives  
- **Highly Specialized Domains**: May lack domain knowledge
- **Code Generation Templates**: May be intentionally generic

## Next Steps

- [Output Formats](output-formats.md) - Understanding different output formats
- [Configuration](../configuration/config-file.md) - Customize trust score calculation
- [CI/CD Integration](../guide/ci-cd-integration.md) - Use trust scores in automation