# Code Analyzer

The code analyzer detects issues in source code including hallucinated imports, invalid APIs, and syntax problems.

## Supported Languages

- **Python**: Full support for imports, function calls, and syntax
- **JavaScript/TypeScript**: Module imports, API calls, and common patterns
- **Go**: Package imports and basic function validation
- **Rust**: Crate dependencies and function calls

## Detection Features

### Import Validation
Checks that imported packages actually exist in package repositories.

### API Verification  
Validates that called functions and methods are real and properly used.

### Syntax Analysis
Detects syntax errors and malformed code structures.

*This page is under development. See [Hallucination Detection](hallucination-detection.md) for detailed examples.*