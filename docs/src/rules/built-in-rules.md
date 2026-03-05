# Built-in Rules

Reference for all built-in rules that come with Vow.

## Code Analysis Rules

### hallucinated-import
- **Severity**: High
- **Description**: Detects imports of non-existent packages
- **Languages**: Python, JavaScript, TypeScript, Go, Rust

### hallucinated-api
- **Severity**: Medium  
- **Description**: Identifies likely fabricated API endpoints
- **Languages**: All

### invalid-function-call
- **Severity**: Medium
- **Description**: Calls to non-existent functions or methods
- **Languages**: Python, JavaScript, TypeScript

## Security Rules

### hardcoded-secret
- **Severity**: High
- **Description**: Detects hardcoded API keys, passwords, and tokens
- **Languages**: All

### dangerous-function
- **Severity**: High
- **Description**: Usage of dangerous functions like eval(), exec()
- **Languages**: Python, JavaScript

### sql-injection-pattern
- **Severity**: High
- **Description**: Potential SQL injection vulnerabilities
- **Languages**: All

## Text Analysis Rules

### broken-reference
- **Severity**: Low
- **Description**: Invalid URLs, links, and citations
- **Languages**: Markdown, reStructuredText

### factual-inconsistency
- **Severity**: Medium
- **Description**: Statements that contradict known facts
- **Languages**: All text

*This page is under development.*